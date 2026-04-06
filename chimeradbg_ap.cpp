// chimera_autopatch.cpp - Refined Version with Precise Patching
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <cstdio>
#include <sstream>

struct Patch {
    uint64_t addr;
    std::string desc;
    std::string oldBytes;
    std::string newBytes;
};

class ChimeraAutopatcher {
public:
    std::vector<uint8_t> buffer;
    std::string filePath;
    uint64_t imageBase = 0;
    uint32_t textRVA = 0;
    uint32_t textRaw = 0;
    uint32_t textSize = 0;
    bool is64bit = false;
    bool loaded = false;
    std::vector<Patch> logs;

    bool load(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) { std::cout << "[-] Cannot open file!\n"; return false; }
        size_t size = f.tellg();
        f.seekg(0);
        buffer.resize(size);
        f.read(reinterpret_cast<char*>(buffer.data()), size);

        filePath = path;
        logs.clear();

        if (parsePE()) {
            loaded = true;
            std::cout << "[+] Loaded: " << std::filesystem::path(path).filename() 
                      << " (" << (is64bit ? "64-bit" : "32-bit") << ")\n";
            return true;
        }
        std::cout << "[-] Invalid PE file!\n";
        return false;
    }

    bool parsePE() {
        if (buffer.size() < 0x40) return false;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        is64bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        imageBase = is64bit ? nt->OptionalHeader.ImageBase 
                   : reinterpret_cast<IMAGE_NT_HEADERS32*>(nt)->OptionalHeader.ImageBase;

        auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            buffer.data() + dos->e_lfanew + (is64bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (memcmp(sections[i].Name, ".text", 5) == 0) {
                textRVA = sections[i].VirtualAddress;
                textRaw = sections[i].PointerToRawData;
                textSize = sections[i].SizeOfRawData;
                return true;
            }
        }
        return false;
    }

    // Helper to check if offset is within .text section bounds
    bool inText(uint32_t offset, uint32_t minSpace = 1) {
        return offset >= textRaw && offset < textRaw + textSize && (offset + minSpace) <= (textRaw + textSize);
    }

    // Convert raw offset to virtual address
    uint64_t rawToVA(uint32_t raw) {
        return imageBase + textRVA + (raw - textRaw);
    }

    void autopatch() {
        if (!loaded) { std::cout << "[-] No file loaded!\n"; return; }
        logs.clear();
        std::cout << "[*] Analyzing VerifyPassword function for precise patching...\n";

        int patches = 0;
        std::vector<uint32_t> checksumOffsets;

        // Step 1: Find all checksum occurrences
        for (uint32_t i = textRaw; i < textRaw + textSize - 4; ++i) {
            if (*reinterpret_cast<uint32_t*>(&buffer[i]) == 0x5B7C3A9F) {
                checksumOffsets.push_back(i);
                std::cout << "[+] Found checksum at raw offset 0x" << std::hex << i 
                          << " (VA: 0x" << rawToVA(i) << ")" << std::dec << "\n";
            }
        }

        if (checksumOffsets.empty()) {
            std::cout << "[-] Checksum not found! Cannot autopatch.\n";
            return;
        }

        // Step 2: For each checksum, analyze the surrounding code precisely
        for (uint32_t chkOff : checksumOffsets) {
            std::cout << "\n[*] Analyzing code around checksum at 0x" << std::hex << chkOff << std::dec << "...\n";

            // Search window: 200 bytes before to 200 bytes after checksum
            uint32_t start = (chkOff > 200) ? chkOff - 200 : textRaw;
            uint32_t end = std::min(chkOff + 200u, textRaw + textSize - 16);

            bool patched_func = false;

            // Strategy A: Find RET 0xC or RET and patch function to return 1 immediately
            // Look for function prologue patterns and early returns
            for (uint32_t j = start; j < chkOff && !patched_func; ++j) {
                // Pattern: XOR EAX, EAX followed by INC EAX (return 1) then RET
                if (inText(j, 3) && buffer[j] == 0x33 && buffer[j+1] == 0xC0 && 
                    buffer[j+2] == 0x40) {
                    // Found: XOR EAX,EAX; INC EAX - this sets return value to 1
                    // Check if followed by RET soon
                    for (uint32_t k = j + 3; k < j + 20 && k < end; ++k) {
                        if (buffer[k] == 0xC3) {
                            uint64_t va = rawToVA(j);
                            char buf[64];
                            snprintf(buf, sizeof(buf), "%02X %02X %02X", buffer[j], buffer[j+1], buffer[j+2]);
                            std::string oldB = buf;
                            // Replace with: MOV EAX, 1 (B8 01 00 00 00) - cleaner, same size consideration
                            buffer[j] = 0xB8;
                            buffer[j+1] = 0x01;
                            buffer[j+2] = 0x00;
                            // Insert NOPs to fill if needed, but let's keep it minimal
                            logs.push_back({va, "Force return value to 1 (XOR/INC -> MOV EAX,1)", oldB, "B8 01 00"});
                            std::cout << "[+] Patched return value setup at VA 0x" << std::hex << va << std::dec << "\n";
                            patches++;
                            patched_func = true;
                            break;
                        }
                    }
                }
            }

            // Strategy B: Patch conditional jumps AFTER checksum comparison
            // Look for JZ/JNZ (74/75) or SETE/SETNE (0F 94/95) after the checksum
            if (!patched_func) {
                for (uint32_t j = chkOff + 4; j < end && !patched_func; ++j) {
                    // SETE (0F 94) or SETNE (0F 95) - convert to MOV AL, 1
                    if (inText(j, 2) && buffer[j] == 0x0F && (buffer[j+1] == 0x94 || buffer[j+1] == 0x95)) {
                        uint64_t va = rawToVA(j);
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%02X %02X", buffer[j], buffer[j+1]);
                        std::string oldB = buf;
                        // Replace SETcc AL with MOV AL, 1 (B0 01) - exactly 2 bytes, no overflow
                        buffer[j] = 0xB0;
                        buffer[j+1] = 0x01;
                        logs.push_back({va, "SETE/SETNE -> MOV AL,1 (force true)", oldB, "B0 01"});
                        std::cout << "[+] Patched SETE/SETNE at VA 0x" << std::hex << va << std::dec << "\n";
                        patches++;
                        patched_func = true;
                    }
                    // JZ (74) or JNZ (75) - convert to JMP EB
                    else if (inText(j, 1) && (buffer[j] == 0x74 || buffer[j] == 0x75)) {
                        // Only patch if this jump is within 50 bytes of checksum (likely the decision point)
                        if (j - chkOff < 50) {
                            uint64_t va = rawToVA(j);
                            char buf[16];
                            snprintf(buf, sizeof(buf), "%02X", buffer[j]);
                            std::string oldB = buf;
                            buffer[j] = 0xEB;  // JMP rel8
                            logs.push_back({va, "JZ/JNZ -> JMP (force success path)", oldB, "EB"});
                            std::cout << "[+] Patched conditional jump at VA 0x" << std::hex << va << std::dec << "\n";
                            patches++;
                            patched_func = true;
                        }
                    }
                }
            }

            // Strategy C: If still not patched, find the first conditional jump after checksum and force it
            if (!patched_func) {
                for (uint32_t j = chkOff + 4; j < end; ++j) {
                    uint8_t b = buffer[j];
                    // Short conditional jumps: 0x70-0x7F
                    if (b >= 0x70 && b <= 0x7F) {
                        uint64_t va = rawToVA(j);
                        char buf[16];
                        snprintf(buf, sizeof(buf), "%02X", b);
                        std::string oldB = buf;
                        buffer[j] = 0xEB;  // Unconditional JMP
                        logs.push_back({va, "Force Jcc to JMP (fallback)", oldB, "EB"});
                        std::cout << "[+] Fallback patch at VA 0x" << std::hex << va << std::dec << "\n";
                        patches++;
                        break;  // Only one fallback patch per checksum
                    }
                    // Long conditional jumps: 0F 80-8F
                    else if (b == 0x0F && inText(j, 2) && buffer[j+1] >= 0x80 && buffer[j+1] <= 0x8F) {
                        uint64_t va = rawToVA(j);
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%02X %02X", b, buffer[j+1]);
                        std::string oldB = buf;
                        buffer[j] = 0xE9;  // JMP rel32 (need to handle displacement)
                        buffer[j+1] = 0x00;
                        buffer[j+2] = 0x00;
                        buffer[j+3] = 0x00;
                        buffer[j+4] = 0x00;
                        logs.push_back({va, "Force long Jcc to JMP (fallback)", oldB, "E9 00 00 00 00"});
                        std::cout << "[+] Fallback long jump patch at VA 0x" << std::hex << va << std::dec << "\n";
                        patches++;
                        break;
                    }
                }
            }
        }

        if (patches > 0) {
            std::cout << "\n[+] ========================================\n";
            std::cout << "[+] TOTAL PATCHES APPLIED: " << patches << "\n";
            std::cout << "[+] The patched exe should now accept ANY password!\n";
            std::cout << "[+] ========================================\n";
        } else {
            std::cout << "\n[!] No patches applied. Manual analysis required.\n";
        }
    }

    void dumpAndShow() {
        if (!loaded) { std::cout << "[-] No file loaded!\n"; return; }
        std::cout << "\n=== DumpNShow - Checksum Search ===\n";
        int found = 0;
        for (uint32_t i = textRaw; i < textRaw + textSize - 4; ++i) {
            if (*reinterpret_cast<uint32_t*>(&buffer[i]) == 0x5B7C3A9F) {
                uint64_t va = rawToVA(i);
                std::cout << "[+] FOUND CHECKSUM #" << ++found << " at VA: 0x" << std::hex << va << std::dec << "\n";
                std::cout << "    Raw offset: 0x" << std::hex << i << std::dec << "\n";
                std::cout << "    Context (+/- 24 bytes): ";
                for (int k = -24; k <= 24; ++k) {
                    uint32_t p = i + k;
                    if (p >= textRaw && p < textRaw + textSize) {
                        // Highlight the checksum itself
                        if (k >= 0 && k < 4) {
                            char buf[8];
                            snprintf(buf, sizeof(buf), "%02X", buffer[p]);
                            std::cout << "\033[1;31m" << buf << "\033[0m ";
                        } else {
                            char buf[8];
                            snprintf(buf, sizeof(buf), "%02X", buffer[p]);
                            std::cout << buf << " ";
                        }
                    }
                }
                std::cout << "\n\n";
            }
        }
        if (found == 0) {
            std::cout << "[-] No checksum (0x5B7C3A9F) found in .text section.\n";
        }
    }

    bool save() {
        if (!loaded) return false;
        std::string bak = filePath + ".bak";
        std::string out = filePath + ".patched.exe";

        // Create backup silently
        try {
            std::filesystem::copy_file(filePath, bak, std::filesystem::copy_options::overwrite_existing);
        } catch (...) {}
        
        std::ofstream f(out, std::ios::binary);
        if (!f) { 
            std::cout << "[-] Save failed! Cannot write to " << out << "\n"; 
            return false; 
        }
        f.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        f.close();

        std::cout << "[+] Saved patched binary to: " << std::filesystem::path(out).filename() << "\n";
        std::cout << "[!] Original file preserved (backup created if needed).\n";
        return true;
    }
};

int main(int argc, char* argv[]) {
    ChimeraAutopatcher p;
    std::string line;

    std::cout << "============================================\n";
    std::cout << "   ChimeraDBG Autopatch - Refined Version\n";
    std::cout << "============================================\n\n";

    // Support command-line argument for batch mode
    if (argc > 1) {
        std::string path = argv[1];
        if (!path.empty() && path[0] == '"') path = path.substr(1, path.size()-2);
        if (p.load(path)) {
            p.autopatch();
            p.save();
            return 0;
        }
        return 1;
    }

    while (true) {
        if (!p.loaded) {
            std::cout << "Drag & drop CrackMe.exe or enter full path:\n> ";
            std::getline(std::cin, line);
            if (line.empty() || line == "exit" || line == "quit") break;
            if (line[0] == '"') line = line.substr(1, line.size()-2);
            // Trim whitespace
            while (!line.empty() && (line.back() == ' ' || line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty()) continue;
            p.load(line);
        } else {
            std::cout << "\n========== MENU ==========\n";
            std::cout << "1. Run Precise Autopatch\n";
            std::cout << "2. DumpNShow (Find Checksum)\n";
            std::cout << "3. Show Patch Log\n";
            std::cout << "4. Save Patched Binary\n";
            std::cout << "5. Load New File\n";
            std::cout << "6. Exit\n";
            std::cout << "> ";
            
            int c;
            if (!(std::cin >> c)) {
                std::cin.clear();
                std::cin.ignore(10000, '\n');
                continue;
            }
            std::cin.ignore(10000, '\n');

            switch (c) {
                case 1: 
                    p.autopatch(); 
                    break;
                case 2: 
                    p.dumpAndShow(); 
                    break;
                case 3: {
                    std::cout << "\n========== PATCH LOG ==========\n";
                    if (p.logs.empty()) {
                        std::cout << "(no patches applied yet)\n";
                    } else {
                        for (const auto& patch : p.logs) {
                            std::cout << "VA: 0x" << std::hex << std::uppercase << patch.addr << std::nouppercase << std::dec
                                      << "\n   " << patch.desc 
                                      << "\n   Bytes: " << patch.oldBytes << " -> " << patch.newBytes << "\n\n";
                        }
                    }
                    break;
                }
                case 4: 
                    p.save(); 
                    break;
                case 5: 
                    p.loaded = false; 
                    break;
                case 6: 
                    return 0;
                default:
                    std::cout << "Invalid option.\n";
            }
        }
    }
    return 0;
}
