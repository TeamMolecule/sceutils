# vita_loader

## Installation

Copy **contents** of `vita_loader` into your `IDA 7.0/loaders` directory.

Place [db.yml](https://raw.githubusercontent.com/vitasdk/vita-headers/master/db.yml) into the directory with your `.elf` files.

When opening a Vita `.elf` file, select "PS Vita ELF [vita_loader.py]" (second option).

## Features

1. Vita ELF loading with import/export parsing
2. `db.yml` from vitasdk used for NID resolving
3. A comment is added to every exported function so you can see if it's exported multiple times using different NIDs/libnids.
4. System instructions like MRC/MCR are automatically commented
5. MOVT/MOVW pairs are detected and appropriate xrefs are added

## Caveats, known bugs, etc

If you load a binary, go to an imported function and decompile it BEFORE decompiling any function that calls into it, it will break its return and arglist detection. Don't do that - there's no reason to.

MOVT/MOVW xrefs detection is not ideal, it does not follow branches.

Relocations are not supported, you won't be able to relocate the file from within IDA.

## License

MIT license, check LICENSE.

System instruction higlighting based on [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight), licensed under MIT.
