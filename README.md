# Subdomain Spider - TEAM VORTEX🚀

A robust and comprehensive subdomain enumeration tool that leverages multiple APIs and techniques to discover subdomains efficiently.

## Features ✨

- **Multi-threaded Processing**: Concurrent subdomain enumeration with configurable thread count
- **Multiple API Integrations**:
  - VirusTotal
  - Shodan
  - SecurityTrails
- **Comprehensive Reporting**:
  - HTML reports with detailed visualization
  - Text-based output
  - Dead subdomain detection
- **Rate Limiting**: Smart API rate limiting to prevent blocking
- **Customizable Configuration**: Easy-to-modify settings via config file

## Prerequisites 📋

- Bash environment (Linux/Unix/WSL)
- curl
- jq
- dig (dnsutils)
- Required API keys:
  - VirusTotal API
  - Shodan API
  - SecurityTrails API

## Installation 🔧

```bash
# Clone the repository
git clone https://github.com/yourusername/subdomain-enum-tool.git

# Navigate to the project directory
cd subdomain-enum-tool

# Make the script executable
chmod +x code.sh
```

## Configuration ⚙️

1. Copy `config.sh.example` to `config.sh`
2. Update the configuration file with your settings:
   - API keys
   - Wordlist path
   - Thread count
   - Team information

```bash
cp config.sh.example config.sh
nano config.sh
```

## Usage 💻

```bash
./code.sh -d example.com
```

### Options

- `-d, --domain`: Target domain
- `-w, --wordlist`: Custom wordlist path
- `-t, --threads`: Number of threads
- `-o, --output`: Output directory
- `-h, --help`: Show help message

## Output Structure 📁

```
output/
├── example.com/
│   ├── subdomains.txt
│   ├── alive_subdomains.txt
│   ├── dead_subdomains.txt
│   ├── report.html
│   └── shodan_results.html
```

## Screenshots 📸

[Add screenshots of your tool's output here]

## Contributing 🤝

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📝

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Authors ✨

- **Raza Ellahi** - Team Lead
- **Laiqa Rafay**
- **Jabir Ishaq**
- **Abdlrehman Farid**
- **Israr Khan**

## Acknowledgments 🙏

- Black Byt3 Internship Program
- [Add any other acknowledgments]

## Disclaimer ⚠️

This tool is for educational and ethical testing purposes only. Users must comply with applicable laws and obtain proper authorization before scanning any domains.

---
Made with ❤️ by Team Vortex
