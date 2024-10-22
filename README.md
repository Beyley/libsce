# libsce

A library to decrypt, decompress, and disassemble files used by various Sony systems.

## Supported formats

- SELF Certified File (PS3)

## TODO

- [ ] RIF + act.dat + IDPS support for decrypting digital copies
- [x] fSELF extraction
- [x] Remove `unreachable`/`panic` from as many places as possible
- [ ] (f)SELF/CF creation/encryption

## TODO: selftool

- [x] Add command to dump info about SELF (shouldn't require any keys to dump basic info)
- [x] Add command to extract ELF file from (f)SELF

## TODO: c_abi

- [x] Extract NPDRM SELF content IDs
- [ ] Unpack (f)SELF files
- [ ] Pack (f)SELF files
