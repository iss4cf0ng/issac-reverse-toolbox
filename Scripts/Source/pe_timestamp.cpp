//pe_timestamp.cpp
//Author: iss4cf0ng/ISSAC

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <cstring>
#include <iomanip>

// PE Header structures
#pragma pack(push, 1)

struct DOS_HEADER {
    uint16_t e_magic;      // MZ
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;     // Offset to PE header
};

struct FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;      // ← PE compile timestamp
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

// Debug directory entry
struct DEBUG_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;      // ← Debug timestamp
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};

// CodeView PDB info (type 2 = CV_INFO_PDB70)
struct CV_INFO_PDB70 {
    uint32_t CvSignature;   // 'RSDS'
    uint8_t  Signature[16]; // GUID
    uint32_t Age;
    char     PdbFileName[1]; // variable length
};

#pragma pack(pop)

std::string formatTimestamp(uint32_t ts) {
    if (ts == 0) return "(zero / not set)";
    time_t t = (time_t)ts;
    char buf[64];
    struct tm* gmt = gmtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", gmt);
    return std::string(buf) + " (0x" + [&]{
        char h[16]; snprintf(h, sizeof(h), "%08X", ts); return std::string(h);
    }() + ")";
}

std::string machineStr(uint16_t m) {
    switch (m) {
        case 0x014c: return "x86 (32-bit)";
        case 0x8664: return "x64 (64-bit)";
        case 0x01c4: return "ARM";
        case 0xaa64: return "ARM64";
        default:     return "Unknown (0x" + [&]{ char h[8]; snprintf(h,8,"%04X",m); return std::string(h); }() + ")";
    }
}

std::string subsystemStr(uint16_t s) {
    switch (s) {
        case 2: return "GUI";
        case 3: return "Console (CUI)";
        case 9: return "Windows CE";
        default: return "Other (" + std::to_string(s) + ")";
    }
}

// RVA → file offset using section table
uint32_t rvaToOffset(uint32_t rva, const std::vector<SECTION_HEADER>& sections) {
    for (const auto& s : sections) {
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData) {
            return s.PointerToRawData + (rva - s.VirtualAddress);
        }
    }
    return 0;
}

void analyze(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "[!] Cannot open: " << path << "\n";
        return;
    }

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  File: " << path << "\n";
    std::cout << "========================================\n";

    DOS_HEADER dos;
    f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != 0x5A4D) { // 'MZ'
        std::cout << "[!] Not a valid PE file (no MZ signature)\n";
        return;
    }

    f.seekg(dos.e_lfanew);
    uint32_t peSig;
    f.read(reinterpret_cast<char*>(&peSig), 4);
    if (peSig != 0x00004550) { // 'PE\0\0'
        std::cout << "[!] Not a valid PE file (no PE signature)\n";
        return;
    }

    FILE_HEADER fh;
    f.read(reinterpret_cast<char*>(&fh), sizeof(fh));

    std::cout << "\n[PE File Header]\n";
    std::cout << "  Architecture     : " << machineStr(fh.Machine) << "\n";
    std::cout << "  Sections         : " << fh.NumberOfSections << "\n";
    std::cout << "  Compile Timestamp: " << formatTimestamp(fh.TimeDateStamp) << "\n";

    uint16_t magic;
    f.read(reinterpret_cast<char*>(&magic), 2);
    f.seekg(-2, std::ios::cur);

    bool is64 = (magic == 0x20B);
    DATA_DIRECTORY debugDir = {0, 0};
    uint16_t subsystem = 0;
    uint8_t linkerMaj = 0, linkerMin = 0;

    if (is64) {
        OPTIONAL_HEADER64 oh;
        f.read(reinterpret_cast<char*>(&oh), sizeof(oh));
        subsystem = oh.Subsystem;
        linkerMaj = oh.MajorLinkerVersion;
        linkerMin = oh.MinorLinkerVersion;
        if (oh.NumberOfRvaAndSizes > 6)
            debugDir = oh.DataDirectory[6]; // IMAGE_DIRECTORY_ENTRY_DEBUG = 6
    } else {
        OPTIONAL_HEADER32 oh;
        f.read(reinterpret_cast<char*>(&oh), sizeof(oh));
        subsystem = oh.Subsystem;
        linkerMaj = oh.MajorLinkerVersion;
        linkerMin = oh.MinorLinkerVersion;
        if (oh.NumberOfRvaAndSizes > 6)
            debugDir = oh.DataDirectory[6];
    }

    std::cout << "  Subsystem        : " << subsystemStr(subsystem) << "\n";
    std::cout << "  Linker Version   : " << (int)linkerMaj << "." << (int)linkerMin << "\n";

    std::vector<SECTION_HEADER> sections(fh.NumberOfSections);
    f.read(reinterpret_cast<char*>(sections.data()), fh.NumberOfSections * sizeof(SECTION_HEADER));

    std::cout << "\n[Sections]\n";
    for (const auto& s : sections) {
        char name[9] = {};
        memcpy(name, s.Name, 8);
        std::cout << "  " << std::left << std::setw(10) << name
                  << " VirtualAddr=0x" << std::hex << std::setw(8) << std::setfill('0') << s.VirtualAddress
                  << " RawSize=0x" << std::setw(8) << s.SizeOfRawData
                  << std::dec << std::setfill(' ') << "\n";
    }

    if (debugDir.VirtualAddress == 0 || debugDir.Size == 0) {
        std::cout << "\n[Debug Directory]\n  (none found)\n";
        return;
    }

    uint32_t debugOffset = rvaToOffset(debugDir.VirtualAddress, sections);
    if (debugOffset == 0) {
        std::cout << "\n[Debug Directory]\n  (could not resolve RVA)\n";
        return;
    }

    int numEntries = debugDir.Size / sizeof(DEBUG_DIRECTORY);
    std::cout << "\n[Debug Directory] (" << numEntries << " entr" << (numEntries==1?"y":"ies") << ")\n";

    for (int i = 0; i < numEntries; i++) {
        f.seekg(debugOffset + i * sizeof(DEBUG_DIRECTORY));
        DEBUG_DIRECTORY dd;
        f.read(reinterpret_cast<char*>(&dd), sizeof(dd));

        std::string typeStr;
        switch (dd.Type) {
            case 1:  typeStr = "COFF";       break;
            case 2:  typeStr = "CodeView";   break;
            case 3:  typeStr = "FPO";        break;
            case 4:  typeStr = "Misc";       break;
            case 5:  typeStr = "Exception";  break;
            case 9:  typeStr = "ILTCG";      break;
            case 16: typeStr = "Repro";      break;
            default: typeStr = "Type(" + std::to_string(dd.Type) + ")"; break;
        }

        std::cout << "  Entry[" << i << "] Type=" << std::left << std::setw(12) << typeStr
                  << " Timestamp=" << formatTimestamp(dd.TimeDateStamp) << "\n";

        // If CodeView, try to read PDB path
        if (dd.Type == 2 && dd.PointerToRawData != 0 && dd.SizeOfData >= 24) {
            f.seekg(dd.PointerToRawData);
            uint32_t cvSig;
            f.read(reinterpret_cast<char*>(&cvSig), 4);

            if (cvSig == 0x53445352) { // 'RSDS'
                uint8_t guid[16];
                f.read(reinterpret_cast<char*>(guid), 16);
                uint32_t age;
                f.read(reinterpret_cast<char*>(&age), 4);

                // PDB path (null-terminated string)
                std::string pdbPath;
                char c;
                while (f.get(c) && c != '\0') pdbPath += c;

                // Format GUID
                char guidStr[48];
                snprintf(guidStr, sizeof(guidStr),
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    guid[3],guid[2],guid[1],guid[0],
                    guid[5],guid[4], guid[7],guid[6],
                    guid[8],guid[9], guid[10],guid[11],guid[12],guid[13],guid[14],guid[15]);

                std::cout << "           PDB GUID : " << guidStr << "\n";
                std::cout << "           PDB Age  : " << age << "\n";
                std::cout << "           PDB Path : " << pdbPath << "\n";
            }
        }
    }

    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "PE Timestamp Extractor\n";
    std::cout << "======================\n";

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <file1.exe> [file2.exe] ...\n";
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        analyze(argv[i]);
    }

    return 0;
}
