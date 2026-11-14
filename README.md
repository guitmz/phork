# phork

phork is a small self loading packer for SHELF style binaries on Linux x64, written in FASM. It takes a SHELF program and wraps it in a stub, producing one normal executable. When you run it, the stub reads its own file through `/proc/self/exe`, finds the embedded program, loads it into memory and jumps to it without calling `execve`.

This is the companion code for the tmp.0ut article at https://tmpout.sh/5/15.html

## Related projects

phork is the third step in a small series.

* [halfexec](https://github.com/guitmz/halfexec) is a general userland ELF loader for static, PIE and dynamic binaries
* [halfshelf](https://github.com/guitmz/halfshelf) narrows that down to SHELF binaries and adds headless payloads with a separate metadata file
* phork takes the headless payload and metadata from halfshelf and packs them inside the loader itself, so everything ships as a single file

## How it works

A packed file is laid out like this.

```
[stub ELF][metadata][payload][footer]
```

The stub is a regular ELF, so Linux starts it as usual. It reads the footer at the end of its own file, uses it to find the metadata and payload, rebuilds the header info in memory, maps the payload, applies relocations, sets up TLS and rebuilds the stack. The target sees the same argc and argv the packed file was started with.

The metadata and payload can be XORed with a fixed key. This is light obfuscation, not encryption.

## Tools

* `phork` is the loader stub
* `mkpack` builds a packed file from the stub and a SHELF program
* `spack_tool` inspects, validates or extracts the parts of a packed file

## Limits

* The embedded payload must be 1 MB or smaller
* Only SHELF style binaries are accepted, meaning static PIE with one PT_LOAD segment
* No interpreter, so dynamic binaries are refused
* Only a small set of relocations is handled
* Linux x64 only

## Build

You need `fasm`, and `gcc` for the test programs.

```sh
make
```

## Usage

Pack a SHELF program and run it.

```sh
make pack-tool-asm
/tmp/phork_mkpack ./phork program packed [--xor-meta] [--xor-payload]
./packed [args...]
```

Inspect or unpack a packed file.

```sh
make spack-tool-asm
/tmp/phork_spack_tool inspect packed
/tmp/phork_spack_tool validate packed
/tmp/phork_spack_tool extract packed out.meta out.payload
```

Set `PHORK_DEBUG=1` to print what the stub is doing.

## Building a SHELF binary

Link as static PIE with the linker script in `test/static-pie.ld`.

```sh
gcc -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -static-pie -Wl,--no-eh-frame-hdr -Wl,-T,test/static-pie.ld \
    -o program program.c
```

`test/payload_asm.asm` shows a SHELF program written in plain FASM.

## Tests

```sh
make run
make corrupt-tests
```

`make run` packs the C and assembly samples into `/tmp` and runs them, checking the exit code. `make corrupt-tests` damages packed files in several ways and makes sure they are refused. `make inspect`, `make inspect-pack`, `make validate-pack` and `make extract-pack` show the packed files in more detail. `make clean` removes everything.

## Layout

* `phork.asm` is the loader stub
* `utils/` holds `mkpack` and `spack_tool`
* `utils.inc` holds syscall numbers, constants and structures
* `loader/` holds shared code for relocation, stack setup and data
* `test/` holds the sample programs and linker script
