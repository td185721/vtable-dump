// vtable-dump — locate class virtual function tables in an x64 PE file
// and print the function pointer list for each.
//
// Pairs with rtti-dump: that tool recovers class names and hierarchies
// from on-disk RTTI; this tool finds where each class's vtable lives and
// enumerates its virtual function slots.
//
// Algorithm:
//   1. Walk the PE as data; locate all MSVC Complete Object Locators
//      (same approach as rtti-dump).
//   2. For each COL, compute its on-disk absolute address as
//      ImageBase + COL_RVA. MSVC lays out vtables as:
//         [vtable - 1]: pointer to COL (absolute address)
//         [vtable + 0]: first virtual function (absolute address)
//         [vtable + 8]: second virtual function
//         ...
//   3. Scan .rdata for 8-byte values matching each COL's absolute address.
//      The slot immediately after is the start of the vtable.
//   4. Walk forward reading QWORDs; while they point into an executable
//      section (.text), treat them as virtual function pointers. Stop at
//      the first non-text pointer or null.
//
// Build: CMake 3.15+, C++17 (MSVC, MinGW-w64, GCC or Clang). Reads x64 PE
// files on any host OS.

#include "pe_format.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

#pragma pack(push, 1)
struct CompleteObjectLocator {
    std::uint32_t signature;
    std::uint32_t offset;
    std::uint32_t cdOffset;
    std::uint32_t pTypeDescriptor;
    std::uint32_t pClassDescriptor;
    std::uint32_t pSelf;
};
#pragma pack(pop)

// NUL-terminated string at `offset`, cut off at the end of the file if the
// terminator is missing.
std::string cstr_at(const unsigned char* data, std::size_t size, std::size_t offset) {
    std::string out;
    for (std::size_t i = offset; i < size && data[i] != 0; ++i) {
        out.push_back(static_cast<char>(data[i]));
    }
    return out;
}

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "error: cannot open '%s'\n", path.c_str());
        std::exit(1);
    }
    in.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> bytes(size);
    in.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

struct PEView {
    const unsigned char*         data;
    std::size_t                  size;
    const IMAGE_NT_HEADERS64*    nt;
    const IMAGE_SECTION_HEADER*  sections;
    WORD                         section_count;
    std::uint64_t                image_base;

    std::optional<std::size_t> rva_to_offset(std::uint32_t rva) const {
        for (WORD i = 0; i < section_count; ++i) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress &&
                rva < s.VirtualAddress + s.Misc.VirtualSize) {
                const auto off = s.PointerToRawData + (rva - s.VirtualAddress);
                if (off < size) return off;
            }
        }
        return std::nullopt;
    }

    const IMAGE_SECTION_HEADER* section_for_rva(std::uint32_t rva) const {
        for (WORD i = 0; i < section_count; ++i) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress &&
                rva < s.VirtualAddress + s.Misc.VirtualSize) {
                return &sections[i];
            }
        }
        return nullptr;
    }

    bool rva_is_executable(std::uint32_t rva) const {
        const auto* s = section_for_rva(rva);
        if (!s) return false;
        return (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
};

PEView load_pe(const std::vector<unsigned char>& image) {
    PEView view{image.data(), image.size(), nullptr, nullptr, 0, 0};
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::fprintf(stderr, "error: file too small\n");
        std::exit(1);
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::fprintf(stderr, "error: not a PE file\n");
        std::exit(1);
    }
    const auto nt_off = static_cast<std::size_t>(static_cast<DWORD>(dos->e_lfanew));
    if (nt_off > image.size() || image.size() - nt_off < sizeof(IMAGE_NT_HEADERS64)) {
        std::fprintf(stderr, "error: NT headers lie outside the file\n");
        std::exit(1);
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "error: missing PE signature\n");
        std::exit(1);
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::fprintf(stderr, "error: only x64 PE files are supported\n");
        std::exit(1);
    }
    const auto sections_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                              nt->FileHeader.SizeOfOptionalHeader;
    const auto sections_len = std::size_t{nt->FileHeader.NumberOfSections} *
                              sizeof(IMAGE_SECTION_HEADER);
    if (sections_off > image.size() || image.size() - sections_off < sections_len) {
        std::fprintf(stderr, "error: section table lies outside the file\n");
        std::exit(1);
    }
    view.nt            = nt;
    view.sections      = IMAGE_FIRST_SECTION(nt);
    view.section_count = nt->FileHeader.NumberOfSections;
    view.image_base    = nt->OptionalHeader.ImageBase;
    return view;
}

struct COLInfo {
    std::uint32_t col_rva;
    std::uint32_t type_rva;
    std::string   name;
};

std::vector<COLInfo> scan_cols(const PEView& view) {
    std::vector<COLInfo> out;
    for (WORD i = 0; i < view.section_count; ++i) {
        const auto& s = view.sections[i];
        char section_name[9] = {};
        std::memcpy(section_name, s.Name, 8);
        if (std::strncmp(section_name, ".rdata", 6) != 0) continue;

        const auto start = s.PointerToRawData;
        const auto end   = start + s.SizeOfRawData;
        for (std::size_t off = start;
             off + sizeof(CompleteObjectLocator) <= end &&
             off + sizeof(CompleteObjectLocator) <= view.size;
             off += 4) {
            const auto* col = reinterpret_cast<const CompleteObjectLocator*>(view.data + off);
            if (col->signature != 1) continue;
            if (col->pTypeDescriptor == 0 || col->pClassDescriptor == 0) continue;
            const auto col_rva = static_cast<std::uint32_t>(
                s.VirtualAddress + (off - s.PointerToRawData));
            if (col->pSelf != col_rva) continue;

            // Resolve name from TypeDescriptor (name field at offset 16).
            const auto type_off = view.rva_to_offset(col->pTypeDescriptor);
            if (!type_off) continue;
            if (*type_off + 19 >= view.size) continue;
            const char* mangled = reinterpret_cast<const char*>(view.data + *type_off + 16);
            if (mangled[0] != '.' || mangled[1] != '?') continue;

            COLInfo info;
            info.col_rva  = col_rva;
            info.type_rva = col->pTypeDescriptor;
            info.name     = cstr_at(view.data, view.size, *type_off + 16);
            out.push_back(std::move(info));
        }
    }
    return out;
}

struct Vtable {
    std::string               class_name;
    std::uint32_t             vtable_rva;
    std::vector<std::uint32_t> fn_rvas;
};

std::vector<Vtable> find_vtables(const PEView& view, const std::vector<COLInfo>& cols) {
    // Build a map from "absolute address of COL" -> COL info.
    std::unordered_map<std::uint64_t, const COLInfo*> col_addr_to_info;
    col_addr_to_info.reserve(cols.size());
    for (const auto& c : cols) {
        col_addr_to_info.emplace(view.image_base + c.col_rva, &c);
    }

    std::vector<Vtable> result;

    for (WORD i = 0; i < view.section_count; ++i) {
        const auto& s = view.sections[i];
        char section_name[9] = {};
        std::memcpy(section_name, s.Name, 8);
        if (std::strncmp(section_name, ".rdata", 6) != 0) continue;

        const auto raw_start = s.PointerToRawData;
        const auto raw_end   = raw_start + s.SizeOfRawData;
        if (raw_end > view.size) continue;

        // Scan 8-byte aligned QWORDs.
        for (std::size_t off = raw_start;
             off + sizeof(std::uint64_t) <= raw_end;
             off += 8) {
            const auto value = *reinterpret_cast<const std::uint64_t*>(view.data + off);
            const auto it = col_addr_to_info.find(value);
            if (it == col_addr_to_info.end()) continue;

            // Vtable starts one slot after the COL pointer.
            const auto vtable_disk_off = off + 8;
            const auto vtable_rva = static_cast<std::uint32_t>(
                s.VirtualAddress + (vtable_disk_off - s.PointerToRawData));

            // Walk forward collecting executable-section pointers.
            Vtable vt;
            vt.class_name  = it->second->name;
            vt.vtable_rva  = vtable_rva;

            for (std::size_t slot_off = vtable_disk_off;
                 slot_off + sizeof(std::uint64_t) <= raw_end;
                 slot_off += 8) {
                const auto fn_abs = *reinterpret_cast<const std::uint64_t*>(view.data + slot_off);
                if (fn_abs == 0) break;
                if (fn_abs < view.image_base) break;
                const auto fn_rva = static_cast<std::uint32_t>(fn_abs - view.image_base);
                if (!view.rva_is_executable(fn_rva)) break;
                vt.fn_rvas.push_back(fn_rva);
                if (vt.fn_rvas.size() > 1024) break;  // sanity cap
            }
            if (!vt.fn_rvas.empty()) result.push_back(std::move(vt));
        }
    }
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    std::size_t max_slots = 32;
    std::string filter;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--max-slots") == 0 && i + 1 < argc) {
            max_slots = static_cast<std::size_t>(std::atoi(argv[++i]));
        } else if ((std::strcmp(argv[i], "--filter") == 0 ||
                    std::strcmp(argv[i], "-f") == 0) && i + 1 < argc) {
            filter = argv[++i];
        } else if (!path) {
            path = argv[i];
        }
    }

    if (!path) {
        std::fprintf(stderr,
                     "usage: %s [--max-slots N] [--filter|-f SUBSTRING] <file.exe|file.dll>\n",
                     argc ? argv[0] : "vtable-dump");
        return 2;
    }

    auto image = read_file(path);
    auto view  = load_pe(image);

    std::printf("[*] scanning for Complete Object Locators ...\n");
    const auto cols = scan_cols(view);
    std::printf("    found %zu COL(s)\n", cols.size());

    std::printf("[*] scanning for vtables that reference them ...\n");
    const auto vtables = find_vtables(view, cols);
    if (filter.empty()) {
        std::printf("    found %zu vtable(s)\n\n", vtables.size());
    } else {
        std::printf("    found %zu vtable(s); filtering by '%s'\n\n",
                    vtables.size(), filter.c_str());
    }

    std::size_t shown = 0;
    for (const auto& vt : vtables) {
        if (!filter.empty() && vt.class_name.find(filter) == std::string::npos) continue;
        ++shown;
        std::printf("%s\n", vt.class_name.c_str());
        std::printf("  vtable RVA : 0x%08lx\n", static_cast<unsigned long>(vt.vtable_rva));
        std::printf("  slot count : %zu\n", vt.fn_rvas.size());
        const auto to_print = (vt.fn_rvas.size() < max_slots) ? vt.fn_rvas.size() : max_slots;
        for (std::size_t i = 0; i < to_print; ++i) {
            std::printf("    [%2zu] fn @ RVA 0x%08lx\n", i,
                        static_cast<unsigned long>(vt.fn_rvas[i]));
        }
        if (vt.fn_rvas.size() > to_print) {
            std::printf("    ... (%zu more; use --max-slots N to show more)\n",
                        vt.fn_rvas.size() - to_print);
        }
        std::printf("\n");
    }
    if (!filter.empty()) {
        std::printf("[*] %zu of %zu vtable(s) matched the filter\n",
                    shown, vtables.size());
    }
    return 0;
}
