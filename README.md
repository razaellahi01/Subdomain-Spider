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
git clone https://github.com/razaellahi01/Subdomain-Spider.git

# Navigate to the project directory
cd Subdomain-spider

# Make the script executable
chmod +x subdomain-spider.sh
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
bash subdomain-spider.sh
```

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

<img width="840" height="334" alt="image" src="https://github.com/user-attachments/assets/405bd003-dcf4-4451-abb7-9662b22fdb11" />
### Identifying Live & Dead Subdomains
<img width="484" height="388" alt="image" src="https://github.com/user-attachments/assets/ae2f916c-7e2e-4b10-a0d1-13bae94aec37" />
### Extracting IP Addresses
<img width="641" height="500" alt="image" src="https://github.com/user-attachments/assets/4a38a4fc-ed1a-4486-81ad-cad127098aa0" />


## Authors ✨

- **Raza Ellahi** - Team Lead
- **Laiqa Rafay**
- **Jabir Ishaq**
- **Abdlrehman Farid**
- **Israr Khan**

## Disclaimer ⚠️

This tool is for educational and ethical testing purposes only. Users must comply with applicable laws and obtain proper authorization before scanning any domains.

---
Made with ❤️ by Team Vortex
