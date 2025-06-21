# dmadump
A personal tool for dumping PE modules and resolving dynamic imports from kernel or user-mode via DMA. Built to suit my own use cases, but others may find it useful.

## Features
- Easily extensible: implement your own `Dumper` or `IATResolver`
- Basic IAT resolver (scans data sections for function pointers)
- Supports only 64-bit targets

## Usage
```sh
# Dump a kernel module using an FPGA-based DMA device
./dmadump-cli --module AntiCheat.sys --method fpga --iat dynamic

# Dump a user-mode module from a process via Win32 API
./dmadump-cli --process game.exe --module game.exe --method win32 --iat dynamic

# Dump via VMware-based memory access (note: you may need to run this as administrator)
./dmadump-cli --process ping.exe --module ping.exe --method vmware://ro=1 --iat dynamic
```

## Building
```sh
cmake -B build
cmake --build build --config Release
```
Then place the required dependencies from the [MemProcFS v5.14 release](https://github.com/ufrisk/MemProcFS/releases/tag/v5.14) into your working directory.

## Supported Platforms
- Windows (MSVC)
- macOS (Clang)
