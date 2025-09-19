# HashBaker

A comprehensive hash extraction tool for password-protected files across multiple formats. HashBaker automatically detects file types and extracts hashes suitable for password cracking with tools like John the Ripper and Hashcat.

## Description

HashBaker is a Python-based tool designed to extract password hashes from various protected file formats. It supports automatic dependency installation, intelligent file type detection, and generates hash outputs compatible with popular password cracking tools.

## Features

- **Multi-format Support**: PDF, ZIP, RAR, 7z, Office documents, PCAP, and NTDS files
- **Automatic Installation**: Installs required system packages when run as root
- **Intelligent Detection**: Automatically detects file types using file extensions and MIME types
- **External Tool Integration**: Leverages existing tools like John the Ripper, Hashcat, and hcxtools
- **Minimal Output**: Clean, parseable output for integration with other tools
- **Python Dependency Management**: Automatically installs required Python packages

## Requirements

### System Requirements
- Linux-based operating system (tested on Ubuntu/Debian)
- Python 3.6 or higher
- Root access for automatic dependency installation
- Internet connection for downloading helper scripts

### Dependencies
The following tools are automatically installed when run as root:
- john (John the Ripper)
- hashcat
- hcxtools
- p7zip-full
- unzip
- unrar-free
- perl
- file
- poppler-utils

### Python Dependencies
- pyhanko (automatically installed for PDF extraction)

## Installation

### Quick Install
```bash
sudo su

git clone https://github.com/Prasanth-kumar-s/hashbaker.git

cd hashbaker

chmod +x hashbaker

```
## Usage

```bash 

./hashbaker /path/to/file

```

### Manual Dependency Installation
If you prefer to install dependencies manually:
```bash
sudo apt-get update
sudo apt-get install -y john hashcat hcxtools p7zip-full unzip unrar-free perl file poppler-utils
pip3 install --user pyhanko
```



### Examples
```bash
# Extract hash from a password-protected PDF
./hashbaker document.pdf

# Extract hash from a ZIP file
./hashbaker archive.zip

# Extract hash from an Office document
./hashbaker presentation.pptx

# Extract WPA handshake from PCAP file
./hashbaker capture.pcap

# Extract hash from 7z archive
./hashbaker archive.7z
```

### Command Line Options
```bash
./hashbaker <protected_file_path>
./hashbaker -h                    # Show help message
./hashbaker --help               # Show help message
```

## Supported File Formats

| Format | File Extensions | Extraction Method |
|--------|----------------|-------------------|
| PDF | .pdf | pyhanko-based extraction |
| Office Documents | .doc, .docx, .xls, .xlsx, .ppt, .pptx | office2john |
| ZIP Archives | .zip | zip2john |
| RAR Archives | .rar | rar2john |
| 7-Zip Archives | .7z | 7z2hashcat |
| Network Captures | .pcap, .cap, .pcapng | hcxpcapngtool/hcxpcaptool |
| NTDS Database | ntds.dit | ntds2john |

## Output

### Success Output
```
[Banner]
Extraction successful.
/path/to/file.hash
```

### Failure Output
```
[Banner]
Extraction failed.
[Error reason]
```

The extracted hash file will have the same name as the input file with a `.hash` extension and will be located in the same directory as the source file.

## Technical Details

### File Type Detection
HashBaker uses multiple methods for file type detection:
1. File extension analysis
2. MIME type detection using the `file` command
3. Special handling for NTDS files based on filename patterns

### Hash Extraction Process
1. **PDF Files**: Uses embedded pyhanko-based extractor for comprehensive PDF security analysis
2. **Office Files**: Leverages John the Ripper's office2john tools
3. **Archive Files**: Uses format-specific John the Ripper tools (zip2john, rar2john)
4. **7z Files**: Downloads and uses 7z2hashcat perl script
5. **PCAP Files**: Uses hcxtools for WPA handshake extraction
6. **NTDS Files**: Uses John the Ripper's ntds2john tools

### Helper Scripts
HashBaker automatically downloads required helper scripts to a local `helper_scripts` directory:
- 7z2hashcat.pl from philsmd/7z2hashcat repository
- pdf2john.py from JohnTheRipper bleeding-jumbo branch

## Troubleshooting

### Common Issues

**"Extraction failed: pyhanko missing"**
- Ensure Python pip is installed: `sudo apt-get install python3-pip`
- Manually install pyhanko: `pip3 install --user pyhanko`

**"Error: must run as root to install dependencies"**
- Run the tool with sudo for first-time setup: `sudo ./hashbaker file.pdf`
- Or manually install dependencies as shown in the installation section

**"Extraction failed: hcxpcapngtool missing"**
- Install hcxtools manually: `sudo apt-get install hcxtools`
- Ensure PCAP file contains WPA handshakes

**"File not found"**
- Check file path and permissions
- Ensure the file exists and is accessible

**"Extraction failed: file format unsupported"**
- Verify the file is actually password-protected
- Check if the file format is in the supported formats list
- Try using the `file` command to verify file type

### Debug Mode
For detailed debugging information, you can modify the script to enable verbose output by changing the `run_quiet` function calls to `run_capture` and examining the output.

## Version History

- **v2.1**: Current version with improved error handling and automatic dependency management
- Enhanced PDF extraction using pyhanko
- Added support for multiple file format detection methods
- Improved output formatting and error reporting

## Author Information

- **Author**: Prasanth-kumar-s
- **GitHub**: https://github.com/Prasanth-kumar-s
- **Tool**: HashBaker
- **Version**: 2.1

## License

This tool is provided as-is for educational and security research purposes. Please ensure you have proper authorization before using this tool on any systems or files you do not own.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bug reports and feature requests.

## Disclaimer

This tool is intended for legitimate security testing and educational purposes only. Users are responsible for complying with applicable laws and regulations. The author is not responsible for any misuse of this tool.