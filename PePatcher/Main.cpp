#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <sstream>

// Define maximum limits
#define MAX_LINE_LENGTH 512
#define MAX_PATCHES 1000

// Structure to hold patch information
struct SPatchEntry {
    uint64_t Offset;
    uint8_t *Data;
    uint32_t Size;

    SPatchEntry() : Offset(0), Data(nullptr), Size(0) {}
    SPatchEntry(uint64_t IOffset, uint8_t *IData, uint32_t ISize)
        : Offset(IOffset), Data(IData), Size(ISize) {}
};

// Function to parse escape sequences in replacement strings
void ParseEscapeSequences(const char *input, uint8_t *output, uint32_t *outputLength) {
    const char *src = input;
    uint8_t *dst = output;
    *outputLength = 0;

    while (*src && *outputLength < MAX_LINE_LENGTH) { // Prevent buffer overflows
        if (*src == '\\') {
            src++;
            switch (*src) {
            case '0': *dst++ = '\0'; break;
            case 't': *dst++ = '\t'; break;
            case 'n': *dst++ = '\n'; break;
            case 'r': *dst++ = '\r'; break;
            case '\\': *dst++ = '\\'; break;
            default:   *dst++ = *src; break; // Copy unsupported escape sequences as-is
            }
        }
        else {
            *dst++ = *src;
        }
        src++;
        (*outputLength)++;
    }
    if (*outputLength == MAX_LINE_LENGTH) {
        std::cerr << "Warning: Escape sequence output truncated to " << MAX_LINE_LENGTH << " bytes.\n";
    }
}

// Function to split a string by a delimiter and return a vector of tokens
std::vector<std::string> SplitString(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Function to parse a single rule line into its components
bool ParseRule(const char *rule, std::vector<std::string> &addressList, uint32_t &replacementLength,
    std::string &replacementString, uint64_t &limit, char &ruleType) {
    std::string ruleStr(rule);

    // Trim any trailing newline or carriage return characters
    ruleStr.erase(std::remove(ruleStr.begin(), ruleStr.end(), '\n'), ruleStr.end());
    ruleStr.erase(std::remove(ruleStr.begin(), ruleStr.end(), '\r'), ruleStr.end());

    if (ruleStr.empty() || ruleStr[0] == '!') return false; // Skip comments or empty lines

    ruleType = ruleStr[0];
    std::string content = ruleStr.substr(1); // Exclude the ruleType character

    std::vector<std::string> parts;

    // Split based on ':' delimiter
    parts = SplitString(content, ':');

    try {
        if (ruleType == '@' || ruleType == '$') {
            if (parts.size() != 3) return false;
            addressList = SplitString(parts[0], ';');
            replacementLength = std::stoul(parts[1]);
            replacementString = parts[2];
        }
        else if (ruleType == '&') {
            if (parts.size() != 3) return false;
            addressList = SplitString(parts[0], ';');
            replacementLength = std::stoul(parts[1]);
            replacementString = parts[2];
        }
        else if (ruleType == '#') {
            if (parts.size() != 4) return false;
            addressList = SplitString(parts[0], ';'); // Although typically single address
            limit = std::stoull(parts[1]);
            replacementLength = std::stoul(parts[2]);
            replacementString = parts[3];
        }
        else if (ruleType == '^') {
            if (parts.size() != 3) return false;
            addressList = SplitString(parts[0], ';');
            replacementLength = std::stoul(parts[1]);
            replacementString = parts[2];
        }
        else {
            return false; // Unsupported rule
        }
    }
    catch (const std::exception &e) {
        std::cerr << "Error parsing rule: " << e.what() << "\n";
        return false;
    }

    return true;
}

// Function to apply a single patch rule
bool ApplyPatch(const char *rule, std::vector<SPatchEntry> &patchEntries) {
    std::vector<std::string> addressListStr;
    uint32_t replacementLength = 0;
    std::string replacementString;
    uint64_t limit = 0;
    char ruleType;

    if (!ParseRule(rule, addressListStr, replacementLength, replacementString, limit, ruleType)) {
        // Parsing failed or rule is a comment/empty line
        return false;
    }

    // Calculate the number of additional patches this rule will generate
    size_t additionalPatches = 0;
    if (ruleType == '@' || ruleType == '$') {
        additionalPatches = addressListStr.size();
    }
    else if (ruleType == '^') {
        additionalPatches = addressListStr.size();
    }
    else if (ruleType == '&') {
        additionalPatches = addressListStr.size();
    }
    else if (ruleType == '#') {
        additionalPatches = limit;
    }

    // Check if adding these patches would exceed MAX_PATCHES
    if (patchEntries.size() + additionalPatches > MAX_PATCHES) {
        std::cerr << "Error: Exceeded maximum number of patches (" << MAX_PATCHES << ").\n";
        return true; // Return true to indicate a fatal error and stop processing
    }

    // Process each rule type
    if (ruleType == '@' || ruleType == '$') {
        for (const auto &addrStr : addressListStr) {
            uint64_t address = 0;
            try {
                address = std::stoull(addrStr, nullptr, 16);
            }
            catch (const std::exception &e) {
                std::cerr << "Error parsing address '" << addrStr << "': " << e.what() << "\n";
                return true;
            }

            uint8_t *data = static_cast<uint8_t *>(malloc(replacementLength));
            if (!data) {
                std::cerr << "Error: Memory allocation failed for rule '" << rule << "'.\n";
                return true;
            }

            memcpy(data, replacementString.c_str(), replacementLength);

            patchEntries.emplace_back(address, data, replacementLength);
        }
    }
    else if (ruleType == '^') {
        for (const auto &addrStr : addressListStr) {
            uint64_t address = 0;
            try {
                address = std::stoull(addrStr, nullptr, 16);
            }
            catch (const std::exception &e) {
                std::cerr << "Error parsing address '" << addrStr << "': " << e.what() << "\n";
                return true;
            }

            // Handle escape sequences
            uint8_t parsedData[MAX_LINE_LENGTH];
            uint32_t parsedLength = 0;
            ParseEscapeSequences(replacementString.c_str(), parsedData, &parsedLength);

            uint8_t *data = static_cast<uint8_t *>(malloc(parsedLength));
            if (!data) {
                std::cerr << "Error: Memory allocation failed for rule '" << rule << "'.\n";
                return true;
            }
            memcpy(data, parsedData, parsedLength);

            patchEntries.emplace_back(address, data, parsedLength);
        }
    }
    else if (ruleType == '&') {
        for (const auto &addrStr : addressListStr) {
            uint64_t address = 0;
            try {
                address = std::stoull(addrStr, nullptr, 16);
            }
            catch (const std::exception &e) {
                std::cerr << "Error parsing address '" << addrStr << "': " << e.what() << "\n";
                return true;
            }

            uint8_t *data = static_cast<uint8_t *>(malloc(replacementLength));
            if (!data) {
                std::cerr << "Error: Memory allocation failed for rule '" << rule << "'.\n";
                return true;
            }
            memcpy(data, replacementString.c_str(), replacementLength);

            patchEntries.emplace_back(address, data, replacementLength);
        }
    }
    else if (ruleType == '#') {
        if (addressListStr.empty()) {
            std::cerr << "Error: No address specified for '#' rule.\n";
            return true;
        }
        // Assuming '#' rule typically has a single address
        uint64_t address = 0;
        try {
            address = std::stoull(addressListStr[0], nullptr, 16);
        }
        catch (const std::exception &e) {
            std::cerr << "Error parsing address '" << addressListStr[0] << "': " << e.what() << "\n";
            return true;
        }

        for (uint64_t i = 0; i < limit; ++i) {
            uint8_t *data = static_cast<uint8_t *>(malloc(replacementLength));
            if (!data) {
                std::cerr << "Error: Memory allocation failed for rule '" << rule << "'.\n";
                return true;
            }
            memcpy(data, replacementString.c_str(), replacementLength);

            uint64_t currentOffset = address + (i * replacementLength);
            patchEntries.emplace_back(currentOffset, data, replacementLength);
        }
    }

    return false; // Return false to indicate successful processing
}

// Function to apply all patches to the input file and create the output file
bool ApplyPatches(const char *inputFilePath, const char *outputFilePath, const std::vector<SPatchEntry> &patchEntries) {
    FILE *inputFile = fopen(inputFilePath, "rb");
    if (!inputFile) {
        perror("Error opening input file");
        return true;
    }

    // Determine file size
    if (fseek(inputFile, 0, SEEK_END) != 0) {
        perror("Error seeking to end of input file");
        fclose(inputFile);
        return true;
    }
    long fileSize = ftell(inputFile);
    if (fileSize < 0) {
        perror("Error getting input file size");
        fclose(inputFile);
        return true;
    }
    rewind(inputFile);

    // Allocate memory for file data
    uint8_t *fileData = static_cast<uint8_t *>(malloc(fileSize));
    if (!fileData) {
        perror("Error allocating memory for file data");
        fclose(inputFile);
        return true;
    }

    // Read file data
    size_t bytesRead = fread(fileData, 1, fileSize, inputFile);
    if (bytesRead != static_cast<size_t>(fileSize)) {
        std::cerr << "Error: Mismatch in file size while reading.\n";
        free(fileData);
        fclose(inputFile);
        return true;
    }
    fclose(inputFile);

    // Apply each patch
    for (const auto &patch : patchEntries) {
        if (patch.Offset + patch.Size <= static_cast<uint64_t>(fileSize)) {
            memcpy(fileData + patch.Offset, patch.Data, patch.Size);
        }
        else {
            std::cerr << "Warning: Patch address 0x" << std::hex << patch.Offset
                << " is out of file bounds\n";
        }
    }

    // Open output file for writing
    FILE *outputFile = fopen(outputFilePath, "wb");
    if (!outputFile) {
        perror("Error opening output file");
        free(fileData);
        return true;
    }

    // Write modified data to output file
    size_t bytesWritten = fwrite(fileData, 1, fileSize, outputFile);
    if (bytesWritten != static_cast<size_t>(fileSize)) {
        std::cerr << "Error: Mismatch in file size while writing.\n";
        free(fileData);
        fclose(outputFile);
        return true;
    }

    fclose(outputFile);
    free(fileData);

    return false; // Indicate success
}

// Function to print usage instructions
void PrintUsage() {
    std::cout << "\n";
    std::cout << "########  ######## ########     ###    ########  ######  ##     ## ######## ########  \n";
    std::cout << "##     ## ##       ##     ##   ## ##      ##    ##    ## ##     ## ##       ##     ## \n";
    std::cout << "##     ## ##       ##     ##  ##   ##     ##    ##       ##     ## ##       ##     ## \n";
    std::cout << "########  ######   ########  ##     ##    ##    ##       ######### ######   ########  \n";
    std::cout << "##        ##       ##        #########    ##    ##       ##     ## ##       ##   ##   \n";
    std::cout << "##        ##       ##        ##     ##    ##    ##    ## ##     ## ##       ##    ##  \n";
    std::cout << "##        ######## ##        ##     ##    ##     ######  ##     ## ######## ##     ## \n";
    std::cout << "\n";
    std::cout <<
        "Usage: PePatcher <Replacement-Filepath> <Input-Filepath> <Output-Filepath>\n\n"
        "Replacement.rf Format:\n"
        "  @<Address1>;<Address2>;...:<Replacement-String-Length>:<Replacement-String>\n"
        "    - Replaces <Replacement-String> at the specified <Address1>, <Address2>, etc.\n\n"
        "  ^<Address1>;<Address2>;...:<Replacement-String-Length>:<Replacement-String>\n"
        "    - Replaces <Replacement-String> at the specified <Address1>, <Address2>, etc. Allows \\0 like operators!\n\n"
        "  &<Address1>;<Address2>;...:<Replacement-String-Length>:<Replacement-String>\n"
        "    - Replaces <Replacement-String> at the specified <Address1>, <Address2>, etc.\n\n"
        "  #<Address>:<Replacement-Limit>:<Replacement-String-Length>:<Replacement-String>\n"
        "    - Replaces <Replacement-String> at the specified <Address> up to <Replacement-Limit> times.\n\n"
        "  $<Address1>;<Address2>;...:<Replacement-String-Length>:<Replacement-String>\n"
        "    - Inserts <Replacement-String> at the specified <Address1>, <Address2>, etc.\n";
}

int main(int argc, char **argv) {
    if (argc < 4) {
        PrintUsage();
        return 1;
    }

    const char *replacementFilePath = argv[1];
    const char *inputFilePath = argv[2];
    const char *outputFilePath = argv[3];

    FILE *replacementFile = fopen(replacementFilePath, "r");
    if (!replacementFile) {
        perror("Error opening replacement file");
        return 1;
    }

    std::vector<SPatchEntry> patchEntries;
    char rule[MAX_LINE_LENGTH];

    // Read and process each rule line
    while (fgets(rule, sizeof(rule), replacementFile)) {
        // ApplyPatch returns true if a fatal error occurred (e.g., exceeding MAX_PATCHES)
        if (ApplyPatch(rule, patchEntries)) {
            fclose(replacementFile);
            // Free already allocated patch data before exiting
            for (auto &patch : patchEntries) {
                free(patch.Data);
            }
            return 1;
        }
    }

    fclose(replacementFile);

    // Apply all collected patches
    if (ApplyPatches(inputFilePath, outputFilePath, patchEntries)) {
        // Free allocated patch data before exiting
        for (auto &patch : patchEntries) {
            free(patch.Data);
        }
        return 1;
    }

    // Free allocated patch data after successful application
    for (auto &patch : patchEntries) {
        free(patch.Data);
    }

    std::cout << "Patching complete. Output saved to " << outputFilePath << "\n";
    return 0;
}
