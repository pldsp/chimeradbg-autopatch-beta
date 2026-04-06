// chimera_autopatch.cpp - Most Reliable Version for your CrackMe
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <format>

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

    void autopatch() {
        if (!loaded) { std::cout << "[-] No file loaded!\n"; return; }
        logs.clear();
        std::cout << "[*] Forcing VerifyPassword to always return true...\n";

        int patches = 0;

        // Method 1: Patch SETE / SETNE near the checksum
        for (uint32_t i = textRaw; i < textRaw + textSize - 4; ++i) {
            if (*reinterpret_cast<uint32_t*>(&buffer[i]) == 0x5B7C3A9F) {
                std::cout << "[+] Found checksum at 0x" << std::hex << (imageBase + textRVA + (i - textRaw)) << std::dec << "\n";

                // Look for comparison result instructions
                for (uint32_t j = i - 100; j < i + 100 && j < textRaw + textSize - 3; ++j) {
                    // SETE AL, SETNE AL, or similar
                    if (buffer[j] == 0x0F && (buffer[j+1] == 0x94 || buffer[j+1] == 0x95)) {
                        uint64_t patchVA = imageBase + textRVA + (j - textRaw);
                        std::string oldB = std::format("{:02X} {:02X}", buffer[j], buffer[j+1]);

                        // Force AL = 1 (true)
                        buffer[j]   = 0xB0;  // mov al, 1
                        buffer[j+1] = 0x01;
                        buffer[j+2] = 0x90;  // nop

                        logs.push_back({patchVA, "Patched SETE/SETNE to MOV AL,1 (force true)", oldB, "B0 01 90"});
                        std::cout << "[+] Patched return value at 0x" << std::hex << patchVA << std::dec << "\n";
                        patches++;
                    }

                    // If we see TEST or CMP followed by Jcc, force the jump
                    if ((buffer[j] == 0x85 || buffer[j] == 0x3B) && 
                        (buffer[j+2] == 0x74 || buffer[j+2] == 0x75 || buffer[j+2] == 0x0F)) {
                        uint64_t patchVA = imageBase + textRVA + (j+2 - textRaw);
                        std::string oldB = std::format("{:02X}", buffer[j+2]);

                        buffer[j+2] = 0xEB;   // force unconditional jump to success
                        logs.push_back({patchVA, "Forced Jcc to JMP (success path)", oldB, "EB"});
                        std::cout << "[+] Forced jump at 0x" << std::hex << patchVA << std::dec << "\n";
                        patches++;
                    }
                }
            }
        }

        if (patches == 0) {
            std::cout << "[!] No patchable pattern found. Trying brute force on all Jcc near checksum...\n";
            // Brute force fallback
            for (uint32_t i = textRaw; i < textRaw + textSize - 4; ++i) {
                if (*reinterpret_cast<uint32_t*>(&buffer[i]) == 0x5B7C3A9F) {
                    for (uint32_t j = i - 120; j < i + 120 && j < textRaw + textSize - 2; ++j) {
                        uint8_t b = buffer[j];
                        if ((b >= 0x70 && b <= 0x7F) || (b == 0x0F && buffer[j+1] >= 0x80 && buffer[j+1] <= 0x8F)) {
                            uint64_t va = imageBase + textRVA + (j - textRaw);
                            std::string oldB = (b == 0x0F) ? std::format("{:02X} {:02X}", b, buffer[j+1]) : std::format("{:02X}", b);
                            buffer[j] = 0xEB;
                            if (b == 0x0F) buffer[j+1] = 0x90;
                            logs.push_back({va, "Brute force Jcc patch", oldB, "EB"});
                            std::cout << "[+] Brute force patch at 0x" << std::hex << va << std::dec << "\n";
                            patches++;
                            break;
                        }
                    }
                }
            }
        }

        if (patches > 0) {
            std::cout << "\n[+] TOTAL PATCHES APPLIED: " << patches << "\n";
            std::cout << "[+] The patched exe should now accept ANY password!\n";
        } else {
            std::cout << "[!] Still no patches applied. Please send me the DumpNShow output again.\n";
        }
    }

    void dumpAndShow() {
        if (!loaded) { std::cout << "[-] No file loaded!\n"; return; }
        std::cout << "\n=== DumpNShow - Checksum Search ===\n";
        for (uint32_t i = textRaw; i < textRaw + textSize - 4; ++i) {
            if (*reinterpret_cast<uint32_t*>(&buffer[i]) == 0x5B7C3A9F) {
                uint64_t va = imageBase + textRVA + (i - textRaw);
                std::cout << "[+] FOUND CHECKSUM at 0x" << std::hex << va << std::dec << "\n";
                std::cout << "    Raw offset: 0x" << std::hex << i << std::dec << "\n";
                std::cout << "    Context: ";
                for (int k = -24; k <= 24; ++k) {
                    uint32_t p = i + k;
                    if (p >= textRaw && p < textRaw + textSize)
                        std::cout << std::format("{:02X} ", buffer[p]);
                }
                std::cout << "\n\n";
            }
        }
    }

    bool save() {
        if (!loaded) return false;
        std::string bak = filePath + ".bak";
        std::string out = filePath + ".patched.exe";

        std::filesystem::rename(filePath, bak);
        std::ofstream f(out, std::ios::binary);
        if (!f) { std::cout << "[-] Save failed!\n"; return false; }
        f.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        f.close();

        std::cout << "[+] Saved: " << std::filesystem::path(out).filename() << "\n";
        return true;
    }
};

int main() {
    ChimeraAutopatcher p;
    std::string line;

    std::cout << "============================================\n";
    std::cout << "      ChimeraDBG Autopatch - Ultra Mode\n";
    std::cout << "============================================\n\n";

    int argc; 
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc > 1) {
        std::wstring w(argv[1]);
        std::string path(w.begin(), w.end());
        if (!path.empty() && path[0] == '"') path = path.substr(1, path.size()-2);
        p.load(path);
    }
    LocalFree(argv);

    while (true) {
        if (!p.loaded) {
            std::cout << "Drag & drop CrackMe.exe or enter full path:\n> ";
            std::getline(std::cin, line);
            if (line.empty() || line == "exit") break;
            if (line[0] == '"') line = line.substr(1, line.size()-2);
            p.load(line);
        } else {
            std::cout << "\nMenu:\n";
            std::cout << "1. Run Ultra Autopatch (Force Success)\n";
            std::cout << "2. DumpNShow\n";
            std::cout << "3. Show Patch Log\n";
            std::cout << "4. Save Patched File\n";
            std::cout << "5. Load New File\n";
            std::cout << "6. Exit\n> ";
            int c;
            std::cin >> c;
            std::cin.ignore();

            if (c == 1) p.autopatch();
            else if (c == 2) p.dumpAndShow();
            else if (c == 3) {
                std::cout << "\n--- Patch Log ---\n";
                for (const auto& patch : p.logs) {
                    std::cout << "0x" << std::hex << std::uppercase << patch.addr 
                              << " | " << patch.desc 
                              << " | Old: " << patch.oldBytes << " -> New: " << patch.newBytes << "\n";
                }
                std::cout << std::dec;
            }
            else if (c == 4) p.save();
            else if (c == 5) p.loaded = false;
            else if (c == 6) break;
        }
        std::cout << "\nPress Enter to continue...";
        std::getchar();
    }
    return 0;
}
