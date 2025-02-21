# Process Hollowing POC

## Features

- Support for 64-bit PE files
- Handles PE files with and without relocations
- Clean process cleanup on failure
- Detailed error reporting
- RAII-style handle management

## Requirements

- Windows OS (Tested on Windows 10)
- Visual Studio 2019 or later
- Windows SDK
- C++17 or later

## Building

1. Clone the repository
2. Open the solution in Visual Studio
3. Build the solution (Release x64 configuration recommended)

## Usage

```bash
process_hollowing.exe <pe_file> <target_process>
```

Example:
```bash
process_hollowing.exe malware.exe c:\windows\system32\notepad.exe
```

## Project Structure

- `main.cpp` - Entry point and command-line interface
- `process_hollowing.h` - Process hollowing class declaration
- `process_hollowing.cpp` - Process hollowing implementation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.