# py_ref

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![LIEF](https://img.shields.io/badge/lief-supported-success.svg)
![Capstone](https://img.shields.io/badge/capstone-supported-success.svg)

**A powerful CLI tool for Portable Executable (PE) binary analysis, cross-reference discovery, and backward-slicing argument recovery.**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Configuration](#configuration) • [How It Works](#how-it-works)

## Overview

`py_ref` is a static analysis utility tailored for reverse engineers and malware analysts. It parses PE files, resolves Import Address Tables (IAT), locates cross-references (Xrefs) to specific target library functions, and performs backward slicing to recover function arguments.

By leveraging **LIEF** for PE parsing and **Capstone** for recursive-descent disassembly, `py_ref` can intelligently track register states (e.g., `RCX`, `RDX`) and stack pushes across varying architectures and Application Binary Interfaces (ABIs).

## Features

* **Multi-Architecture Support**: Analyze `x86`, `x86_64`, and `arm64` binaries.
* **ABI-Aware Argument Recovery**: Automatically handles different calling conventions:
  * `windows` (x64 fastcall & shadow space)
  * `cdecl` / `stdcall` (x86 push tracking)
  * `aapcs` (ARM64)
* **Hybrid Disassembly**: Combines recursive-descent control flow analysis with linear gap-finding heuristics to discover unreferenced functions and skip alignment padding (e.g., `INT3`).
* **Configurable Backward Slicing**: Define custom instruction look-back windows to fine-tune argument recovery.
* **Rich Reporting**: Export results as machine-readable `JSON` or interactive, dark-mode `HTML` reports.

## Installation

### Prerequisites

* **Python 3.8+**

Install the required dependencies via pip:

```bash
pip install lief capstone jinja2
```

*(Alternatively, if you have a `requirements.txt` file, run `pip install -r requirements.txt`)*

## Usage

Execution is driven via command-line arguments. You must provide a target binary and a JSON file specifying the functions you want to track.

### Basic Analysis (HTML Output)

Analyze an `x86_64` PE binary using default configurations and output a styled HTML report:

```bash
python py_ref.py -b samples/sample.exe -funcs samples/funcs.json -f html -o report.html
```

### Advanced Analysis (Custom ABI & Verbose Mode)

Run analysis on an `x86` binary, manually specify the architecture and ABI, increase the look-back window to 15 instructions, and enable verbose logging:

```bash
python py_ref.py -b samples/sample32.exe -funcs samples/funcs.json --arch x86 --abi cdecl -w 15 -v -f json
```

## Command-Line Arguments

| Flag / Option | Type | Required | Default | Description | 
| ----- | ----- | ----- | ----- | ----- | 
| `-b`, `--binary` | `Path` | **Yes** | `None` | Target PE binary file to analyze. | 
| `-funcs`, `--functions` | `Path` | **Yes** | `None` | JSON file specifying target functions for Xref search. | 
| `--config` | `Path` | No | `./rsc/config.json` | Path to the JSON configuration file. | 
| `--arch` | `str` | No | *Config default* | Target architecture (`x86`, `x86_64`, `aarch64`). | 
| `--abi` | `str` | No | *Config default* | Calling convention ABI for argument recovery. | 
| `-f`, `--format` | `str` | No | *Config default* | Output report format (`html` or `json`). | 
| `-o`, `--output` | `Path` | No | `./output.<fmt>` | Destination path for the analysis report. | 
| `-w`, `--window` | `int` | No | *Config default* | Look-back instruction window for backward slicing. | 
| `-v`, `--verbose` | `bool` | No | `False` | Enables verbose logging output during disassembly. | 

## How It Works (The Pipeline)

1. **Initialization**: CLI arguments are parsed and validated against `rsc/config.json`.
2. **PE Parsing**: Uses `LIEF` to load the binary, extract the `.text` executable section, calculate the Entry Point RVA, and map the Import Address Table (IAT).
3. **Disassembly**: The Capstone engine performs a recursive-descent disassembly starting from the entry point, mapping call sites to imported symbols.
4. **Backward Slicing**: When a target function is found, the engine scans backward up to the `--window` limit, identifying stack pushes or register assignments corresponding to the active ABI.
5. **Data Export**: Results (including instruction slices and argument `REG`/`STACK` locations) are serialized to JSON or rendered via `Jinja2` into a responsive HTML view.

## Configuration (`config.json`)

The `rsc/config.json` file dictates the supported architectures, ABIs, and default fallbacks. You can easily extend `py_ref` to support custom ABIs by modifying this schema:

```json
{
    "architectures": {
        "x86_64": {
            "abis": ["windows", "vector_call"],
            "formats": ["html", "json"]
        }
    },
    "defaults": {
        "arch": "x86_64",
        "abi": "windows",
        "format": "json",
        "window": 15
    }
}
```

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](../../issues).

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.
