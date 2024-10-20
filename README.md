# libsce

A library to decrypt, decompress, and disassemble files used by various Sony systems.

## Supported formats

- Certified File (PS3)

## TODO

- [ ] RIF + act.dat + IDPS support for decrypting digital copies
- [ ] fSELF support
- [x] Remove `unreachable`/`panic` from as many places as possible
- [ ] Make a C interface for creating and unpacking SELF files
- [ ] SELF/CF creation/encryption

## TODO: selftool

- [ ] Add command to dump info about SELF (shouldn't require any keys to dump basic info)
