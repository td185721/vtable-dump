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
#include "term.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace demangle {

// Simple MSVC type_info name demangler.
// Handles the common ".?A[VUW]Name@ns@...@@" form by stripping the
// RTTI prefix (`.?A`), stripping the trailing `@@`, splitting the body
// on `@`, reversing, and joining with `::`.
//
// Template names (identified by the `?$` sequence) are returned as-is;
// their parameter grammar is non-trivial to parse and out of scope here.
inline std::string type_info(const std::string& mangled) {
    if (mangled.size() < 6) return mangled;
    if (mangled[0] != '.' || mangled[1] != '?' || mangled[2] != 'A') return mangled;
    const char tag = mangled[3];
    if (tag != 'V' && tag != 'U' && tag != 'W') return mangled;
    if (mangled.compare(mangled.size() - 2, 2, "@@") != 0) return mangled;

    const auto body = mangled.substr(4, mangled.size() - 4 - 2);
    if (body.find("?$") != std::string::npos) return mangled;  // template, bail

    std::vector<std::string> parts;
    std::string cur;
    for (char c : body) {
        if (c == '@') {
            if (!cur.empty()) parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    if (parts.empty()) return mangled;

    std::string out;
    for (std::size_t i = parts.size(); i > 0; --i) {
        if (!out.empty()) out += "::";
        out += parts[i - 1];
    }
    return out;
}

}  // namespace demangle

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
    bool demangle_names = false;
    bool bad_flag = false;
    term::Mode color = term::Mode::Auto;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        const int cf = term::parse_flag(argc, argv, i, color);
        if (cf != 0) {
            bad_flag |= cf < 0;
        } else if (std::strcmp(argv[i], "--max-slots") == 0 && i + 1 < argc) {
            max_slots = static_cast<std::size_t>(std::atoi(argv[++i]));
        } else if ((std::strcmp(argv[i], "--filter") == 0 ||
                    std::strcmp(argv[i], "-f") == 0) && i + 1 < argc) {
            filter = argv[++i];
        } else if (std::strcmp(argv[i], "--demangle") == 0 || std::strcmp(argv[i], "-d") == 0) {
            demangle_names = true;
        } else if (!path) {
            path = argv[i];
        }
    }

    if (!path || bad_flag) {
        std::fprintf(stderr,
                     "usage: %s [--max-slots N] [--filter|-f SUBSTRING] [--demangle|-d]"
                     " [--color auto|always|never] <file.exe|file.dll>\n",
                     argc ? argv[0] : "vtable-dump");
        return 2;
    }
    term::init(color);
    const auto *B = term::bold(), *C = term::cyan(), *D = term::dim(), *M = term::magenta(),
               *R = term::reset();

    auto image = read_file(path);
    auto view  = load_pe(image);

    std::printf("%s[*] scanning for Complete Object Locators ...%s\n", D, R);
    const auto cols = scan_cols(view);
    std::printf("%s    found %zu COL(s)%s\n", D, cols.size(), R);

    std::printf("%s[*] scanning for vtables that reference them ...%s\n", D, R);
    const auto vtables = find_vtables(view, cols);
    if (filter.empty()) {
        std::printf("%s    found %zu vtable(s)%s\n\n", D, vtables.size(), R);
    } else {
        std::printf("%s    found %zu vtable(s); filtering by '%s'%s\n\n", D,
                    vtables.size(), filter.c_str(), R);
    }

    std::size_t shown = 0;
    for (const auto& vt : vtables) {
        const auto pretty = demangle::type_info(vt.class_name);
        if (!filter.empty() && vt.class_name.find(filter) == std::string::npos &&
            pretty.find(filter) == std::string::npos) {
            continue;
        }
        ++shown;
        std::printf("%s%s%s%s\n", B, M, (demangle_names ? pretty : vt.class_name).c_str(), R);
        std::printf("  vtable RVA : %s0x%08lx%s\n", C, static_cast<unsigned long>(vt.vtable_rva), R);
        std::printf("  slot count : %s%zu%s\n", B, vt.fn_rvas.size(), R);
        const auto to_print = (vt.fn_rvas.size() < max_slots) ? vt.fn_rvas.size() : max_slots;
        for (std::size_t i = 0; i < to_print; ++i) {
            std::printf("    %s[%2zu]%s fn @ RVA %s0x%08lx%s\n", D, i, R, C,
                        static_cast<unsigned long>(vt.fn_rvas[i]), R);
        }
        if (vt.fn_rvas.size() > to_print) {
            std::printf("    %s... (%zu more; use --max-slots N to show more)%s\n", D,
                        vt.fn_rvas.size() - to_print, R);
        }
        std::printf("\n");
    }
    if (!filter.empty()) {
        std::printf("%s[*] %zu of %zu vtable(s) matched the filter%s\n", D,
                    shown, vtables.size(), R);
    }
    return 0;
}
