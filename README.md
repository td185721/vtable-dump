# vtable-dump

A command-line vtable locator for x64 Windows binaries. Finds the virtual
function tables of classes with MSVC RTTI and prints the list of function
pointers in each slot.

Pairs naturally with [rtti-dump](https://github.com/td185721/rtti-dump) —
`rtti-dump` recovers class names and inheritance hierarchies from on-disk
RTTI; `vtable-dump` finds where each class's vtable actually lives and
enumerates its virtual function slots.

## How it works

MSVC lays out a class vtable with a hidden pointer to the Complete Object
Locator immediately before the first function slot:

```
    [vtable - 1]  →  Complete Object Locator (absolute address)
    [vtable + 0]  →  virtual function #0
    [vtable + 8]  →  virtual function #1
    ...
```

The tool:

1. Walks the PE and finds all Complete Object Locators (the same approach
   as `rtti-dump`).
2. For each COL, computes its absolute address as `ImageBase + COL_RVA`.
3. Scans `.rdata` for QWORDs matching those COL addresses. Each match is
   the "pointer to COL" slot of a real vtable.
4. Walks forward reading QWORDs; while each one is an absolute address
   pointing into an executable section, treats it as a virtual function
   pointer. Stops at the first non-text pointer or null.

The result is a per-class vtable with its RVA, slot count, and function
pointer RVAs.

## Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Usage

```powershell
vtable-dump.exe path\to\binary.exe
vtable-dump.exe path\to\binary.exe --max-slots 128
```

`--max-slots N` controls how many function pointers to print per vtable
(default 32). The remaining slot count is still reported.

## Example output

```
[*] scanning for Complete Object Locators ...
    found 93 COL(s)
[*] scanning for vtables that reference them ...
    found 93 vtable(s)

.?AVexception@std@@
  vtable RVA : 0x00037180
  slot count : 2
    [ 0] fn @ RVA 0x0000a140
    [ 1] fn @ RVA 0x0000a1b0

.?AVbad_alloc@std@@
  vtable RVA : 0x00037200
  slot count : 2
    [ 0] fn @ RVA 0x0000a240
    [ 1] fn @ RVA 0x0000a1b0

...
```

## Scope and limits

- **x64 PE only.** 32-bit MSVC uses absolute pointers in RTTI structures
  with a different layout, not handled here.
- **MSVC convention only.** MinGW / Clang on Windows emit Itanium ABI
  vtables with no Complete Object Locator pointer.
- **Classes without RTTI are invisible.** The tool identifies vtables via
  their COL back-reference. A class compiled with `/GR-` (RTTI disabled)
  has no COL and will not be found.
- **Virtual function order is MSVC-defined.** Slot 0 is the first virtual
  function declared in the derived class; inherited virtuals come first
  in multiple-inheritance base sub-vtables.

## Pairing with rtti-dump

Typical workflow:

1. Run `rtti-dump target.exe` → see class hierarchies and base classes.
2. Run `vtable-dump target.exe` → see where each class's vtable lives and
   what functions sit in each slot.
3. Open the binary in Ghidra or IDA, jump to a function RVA from a
   vtable slot, and inspect the implementation.

Together they give you both the structural and the pointer-level view
of a C++ class in a Windows binary.

## License

MIT — see [LICENSE](LICENSE).
