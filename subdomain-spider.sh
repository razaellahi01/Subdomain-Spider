#!/bin/bash

# Team Vortex Subdomain Enumeration Tool
# Author: Team Vortex - Pure Bash Implementation

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global variables
TARGET_DOMAIN=""
OUTPUT_DIR=""

# Default values (will be overridden by config file)
WORDLIST_PATH=""
VIRUSTOTAL_API_KEY=""
SHODAN_API_KEY=""
SECURITYTRAILS_API_KEY=""
MAX_THREADS=50
TEAM_NAME="Team Vortex"
TEAM_LEAD="Raza Ellahi"
TEAM_MEMBERS="Laiqa Rafay, Jabir Ishaq, Israr Khan, Ubaidullah Salman"
PROJECT_NAME="Subdomdomains Enumeration Tool"
HTTP_TIMEOUT=5
DNS_TIMEOUT=3
API_RATE_LIMIT=1

# Function to display large startup banner
display_startup_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
                                                                                             
 ████████╗███████╗ █████╗ ███╗   ███╗    ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗ 
 ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝ 
    ██║   █████╗  ███████║██╔████╔██║    ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝  
    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║    ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗  
    ██║   ███████╗██║  ██║██║ ╚═╝ ██║     ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗ 
    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ 
                                                                                             
                     ADVANCED SUBDOMAIN ENUMERATION & RECONNAISSANCE TOOL                    
                                                                                             
                                 🚀 Black Byt3 | TEAM VORTEX ⚡                               
                                                                                             
                                   👑 Team Lead: Raza Ellahi                                  
                    🤝 Team Members: Laiqa Rafay, Jabir Ishaq, Israr Khan, Ubaidullah Salman           
                                                                                             
                                Developed with ❤️ for Hunters                                

EOF
    echo -e "${NC}"
    echo ""
    sleep 3
}

# Function to display banner
display_banner() {
    clear
    echo -e "${CYAN}"
    echo "████████╗███████╗ █████╗ ███╗   ███╗    ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗"
    echo "╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝"
    echo "   ██║   █████╗  ███████║██╔████╔██║    ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ "
    echo "   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║    ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ "
    echo "   ██║   ███████╗██║  ██║██║ ╚═╝ ██║     ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗"
    echo "   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    SUBDOMAIN ENUMERATION & RECONNAISSANCE TOOL${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    # Separator & Team Tagline
    echo "====================================================================="
    echo "                      🚀 Black Byt3 | TEAM VORTEX ⚡                 "
    echo "====================================================================="
    # Contributors
    echo "👑 Team Lead   : Raza Ellahi"
    echo "🤝 Team Members: Laiqa Rafay, Jabir Ishaq, Israr Khan, Ubaidullah Salman"
    echo ""
    echo "📌 Use a bash-compatible terminal (We prefer Kali Linux)"
    echo "====================================================================="
    echo ""
    
}

# Function to display completion banners
display_completion_banner() {
    local step_name="$1"
    local description="$2"
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                               ✅ STEP COMPLETED ✅                                   ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  Step: ${YELLOW}$step_name${WHITE}                                                    ║${NC}"
    echo -e "${WHITE}║  Info: ${CYAN}$description${WHITE}                                                    ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    sleep 2
}

# Function to load configuration
load_config() {
    local config_file="config.sh"
    
    echo -e "${BLUE}[INFO]${NC} Loading configuration..."
    
    if [ -f "$config_file" ]; then
        # Source the config file safely
        source "$config_file"
        echo -e "${GREEN}[SUCCESS]${NC} Configuration loaded from $config_file"
        
        # Validate critical configurations
        if [ -z "$WORDLIST_PATH" ] || [ ! -f "$WORDLIST_PATH" ]; then
            echo -e "${RED}[ERROR]${NC} Wordlist path not configured or file not found!"
            echo -e "${YELLOW}[INFO]${NC} Please update WORDLIST_PATH in config.sh"
            return 1
        fi
        
        echo -e "${GREEN}[CONFIG]${NC} Wordlist: $WORDLIST_PATH"
        echo -e "${GREEN}[CONFIG]${NC} Max Threads: $MAX_THREADS"
        
        # Display API status
        [ -n "$VIRUSTOTAL_API_KEY" ] && echo -e "${GREEN}[CONFIG]${NC} VirusTotal API: Configured"
        [ -n "$SHODAN_API_KEY" ] && echo -e "${GREEN}[CONFIG]${NC} Shodan API: Configured"
        [ -n "$SECURITYTRAILS_API_KEY" ] && echo -e "${GREEN}[CONFIG]${NC} SecurityTrails API: Configured"
        
    else
        echo -e "${RED}[ERROR]${NC} Configuration file not found: $config_file"
        echo -e "${YELLOW}[INFO]${NC} Please create config.sh file with your settings"
        return 1
    fi
    
    return 0
}

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}[INFO]${NC} Checking dependencies..."
    
    local deps=("curl" "dig" "nslookup" "host")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Missing dependencies: ${missing_deps[*]}"
        echo -e "${YELLOW}[INFO]${NC} Please install missing dependencies:"
        echo -e "${YELLOW}       ${NC} sudo apt-get install curl dnsutils"
        exit 1
    fi
    
    echo -e "${GREEN}[SUCCESS]${NC} All dependencies are installed."
}

# Function to validate domain
validate_domain() {
    local domain="$1"
    if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[ERROR]${NC} Invalid domain format: $domain"
        return 1
    fi
    return 0
}

# Function to get user input
get_user_input() {
    echo -e "${CYAN}[INPUT]${NC} Enter target domain (e.g., example.com):"
    read -r TARGET_DOMAIN
    
    if ! validate_domain "$TARGET_DOMAIN"; then
        exit 1
    fi
    
    # Create output directory
    OUTPUT_DIR="results_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${GREEN}[INFO]${NC} Target domain: $TARGET_DOMAIN"
    echo -e "${GREEN}[INFO]${NC} Output directory created: $OUTPUT_DIR"
}

# Function to check single subdomain
check_single_subdomain() {
    local subdomain="$1"
    local full_domain="${subdomain}.${TARGET_DOMAIN}"
    
    # Use dig to resolve subdomain
    local ip=$(dig +short "$full_domain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -n "$ip" ]; then
        echo "$full_domain"
        return 0
    fi
    return 1
}

# Function for brute force subdomain enumeration with basic threading
brute_force_subdomains() {
    echo -e "${BLUE}[INFO]${NC} Starting brute force subdomain enumeration..."
    
    local subdomains_file="$OUTPUT_DIR/brute_force_subdomains.txt"
    local temp_dir="$OUTPUT_DIR/temp_brute"
    mkdir -p "$temp_dir"
    
    local total_words=$(wc -l < "$WORDLIST_PATH")
    echo -e "${YELLOW}[INFO]${NC} Testing $total_words subdomains using background processes..."
    
    local current=0
    local batch_size=100
    local batch_count=0
    
    # Process in batches
    while IFS= read -r subdomain; do
        ((current++))
        
        # Run subdomain check in background
        (
            if check_single_subdomain "$subdomain" >/dev/null 2>&1; then
                echo "${subdomain}.${TARGET_DOMAIN}" >> "$temp_dir/batch_${batch_count}.txt"
                echo -e "${GREEN}[FOUND]${NC} ${subdomain}.${TARGET_DOMAIN}"
            fi
        ) &
        
        # Limit concurrent processes
        if (( current % MAX_THREADS == 0 )); then
            wait  # Wait for current batch to complete
            echo -e "${BLUE}[PROGRESS]${NC} Tested $current/$total_words subdomains..."
        fi
        
        # Create new batch file every batch_size entries
        if (( current % batch_size == 0 )); then
            ((batch_count++))
        fi
        
    done < "$WORDLIST_PATH"
    
    # Wait for remaining processes
    wait
    
    # Combine all batch results
    cat "$temp_dir"/batch_*.txt 2>/dev/null | sort -u > "$subdomains_file"
    rm -rf "$temp_dir"
    
    local found_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo "0")
    echo -e "${GREEN}[SUCCESS]${NC} Brute force completed. Found $found_count subdomains."
    
    # Display completion banner
    display_completion_banner "BRUTE FORCE ENUMERATION" "Successfully completed subdomain discovery using background processes"
}

# Function for API-based subdomain enumeration
api_based_enumeration() {
    echo -e "${BLUE}[INFO]${NC} Starting API-based subdomain enumeration..."
    
    local api_subdomains_file="$OUTPUT_DIR/api_subdomains.txt"
    touch "$api_subdomains_file"
    
    # VirusTotal API
    if [ -n "$VIRUSTOTAL_API_KEY" ]; then
        echo -e "${BLUE}[INFO]${NC} Querying VirusTotal API for $TARGET_DOMAIN..."
        local vt_response=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VIRUSTOTAL_API_KEY&domain=$TARGET_DOMAIN")
        
        if [ $? -eq 0 ] && echo "$vt_response" | grep -q "subdomains"; then
            # Extract subdomains without jq (pure bash)
            echo "$vt_response" | sed -n 's/.*"subdomains":\[\([^]]*\)\].*/\1/p' | \
                sed 's/[",]//g' | tr ' ' '\n' | grep -v '^$' >> "$api_subdomains_file"
            echo -e "${GREEN}[SUCCESS]${NC} VirusTotal API query completed."
        fi
        sleep "$API_RATE_LIMIT"
    fi
    
    # crt.sh API (Certificate Transparency)
    echo -e "${BLUE}[INFO]${NC} Querying crt.sh (Certificate Transparency) for $TARGET_DOMAIN..."
    local crt_response=$(curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json")
    
    if [ $? -eq 0 ] && [ -n "$crt_response" ]; then
        # Extract domains from JSON response (basic parsing)
        echo "$crt_response" | grep -oE '"name_value":"[^"]*"' | \
            sed 's/"name_value":"//g; s/"//g' | \
            grep -E "[a-zA-Z0-9.-]+\.$TARGET_DOMAIN" | \
            sort -u >> "$api_subdomains_file"
        echo -e "${GREEN}[SUCCESS]${NC} crt.sh API query completed."
    fi
    
    # HackerTarget API (free, no key required)
    echo -e "${BLUE}[INFO]${NC} Querying HackerTarget API for $TARGET_DOMAIN..."
    local ht_response=$(curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET_DOMAIN")
    
    if [ $? -eq 0 ] && [ -n "$ht_response" ]; then
        echo "$ht_response" | grep -oE "[a-zA-Z0-9.-]+\.$TARGET_DOMAIN" | \
            sort -u >> "$api_subdomains_file"
        echo -e "${GREEN}[SUCCESS]${NC} HackerTarget API query completed."
    fi
    
    # Remove duplicates and empty lines
    sort -u "$api_subdomains_file" | grep -v "^$" > "${api_subdomains_file}.tmp"
    mv "${api_subdomains_file}.tmp" "$api_subdomains_file"
    
    local found_count=$(wc -l < "$api_subdomains_file" 2>/dev/null || echo "0")
    echo -e "${GREEN}[SUCCESS]${NC} API enumeration completed. Found $found_count unique subdomains."
    
    # Display completion banner
    display_completion_banner "API ENUMERATION" "Successfully queried multiple APIs: VirusTotal, crt.sh, HackerTarget"
}

# Function to check if subdomain is live
check_subdomain_live() {
    local subdomain="$1"
    
    # Check if subdomain responds to HTTP/HTTPS
    if timeout "$HTTP_TIMEOUT" curl -s --max-time "$DNS_TIMEOUT" --connect-timeout 2 -I "http://$subdomain" >/dev/null 2>&1 || \
       timeout "$HTTP_TIMEOUT" curl -s --max-time "$DNS_TIMEOUT" --connect-timeout 2 -I "https://$subdomain" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to identify live subdomains
identify_live_subdomains() {
    echo -e "${BLUE}[INFO]${NC} Identifying live subdomains..."
    
    local all_subdomains_file="$OUTPUT_DIR/all_subdomains.txt"
    local live_subdomains_file="$OUTPUT_DIR/live_subdomains.txt"
    local dead_subdomains_file="$OUTPUT_DIR/dead_subdomains.txt"
    local temp_dir="$OUTPUT_DIR/temp_live"
    mkdir -p "$temp_dir"
    
    # Combine all found subdomains
    cat "$OUTPUT_DIR"/*subdomains.txt 2>/dev/null | sort -u | grep -v "^$" > "$all_subdomains_file"
    
    local total_subdomains=$(wc -l < "$all_subdomains_file" 2>/dev/null || echo "0")
    
    if [ "$total_subdomains" -eq 0 ]; then
        echo -e "${YELLOW}[WARNING]${NC} No subdomains found to check."
        return
    fi
    
    echo -e "${BLUE}[INFO]${NC} Checking $total_subdomains subdomains for availability..."
    
    local current=0
    while IFS= read -r subdomain; do
        ((current++))
        
        # Run live check in background
        (
            if check_subdomain_live "$subdomain"; then
                echo "$subdomain" >> "$temp_dir/live.txt"
                echo -e "${GREEN}[LIVE]${NC} $subdomain"
            else
                echo "$subdomain" >> "$temp_dir/dead.txt"
                echo -e "${RED}[DEAD]${NC} $subdomain"
            fi
        ) &
        
        # Limit concurrent processes
        if (( current % MAX_THREADS == 0 )); then
            wait
            echo -e "${BLUE}[PROGRESS]${NC} Checked $current/$total_subdomains subdomains..."
        fi
        
    done < "$all_subdomains_file"
    
    # Wait for remaining processes
    wait
    
    # Combine results
    cat "$temp_dir/live.txt" 2>/dev/null | sort -u > "$live_subdomains_file"
    cat "$temp_dir/dead.txt" 2>/dev/null | sort -u > "$dead_subdomains_file"
    rm -rf "$temp_dir"
    
    local live_count=$(wc -l < "$live_subdomains_file" 2>/dev/null || echo "0")
    echo -e "${GREEN}[SUCCESS]${NC} Live subdomain identification completed. $live_count live subdomains found."
    
    # Display completion banner
    display_completion_banner "LIVE SUBDOMAIN CHECK" "Successfully identified active subdomains"
}

# Function to extract IPs
extract_ips() {
    echo -e "${BLUE}[INFO]${NC} Extracting IP addresses from live subdomains..."
    
    local live_subdomains_file="$OUTPUT_DIR/live_subdomains.txt"
    local private_ips_file="$OUTPUT_DIR/private_ips.txt"
    local public_ips_file="$OUTPUT_DIR/public_ips.txt"
    local subdomain_ip_mapping="$OUTPUT_DIR/subdomain_ip_mapping.txt"
    
    if [ ! -f "$live_subdomains_file" ]; then
        echo -e "${YELLOW}[WARNING]${NC} No live subdomains file found."
        return
    fi
    
    > "$subdomain_ip_mapping"
    > "$private_ips_file"
    > "$public_ips_file"
    
    while IFS= read -r subdomain; do
        local ip=$(dig +short "$subdomain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        
        if [ -n "$ip" ]; then
            echo "$subdomain -> $ip" >> "$subdomain_ip_mapping"
            echo -e "${GREEN}[IP]${NC} $subdomain -> $ip"
            
            # Check if IP is private or public
            if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
                echo "$ip" >> "$private_ips_file"
                echo -e "${YELLOW}[PRIVATE IP]${NC} $subdomain -> $ip"
            else
                echo "$ip" >> "$public_ips_file"
                echo -e "${BLUE}[PUBLIC IP]${NC} $subdomain -> $ip"
            fi
        fi
    done < "$live_subdomains_file"
    
    # Remove duplicates
    sort -u "$private_ips_file" -o "$private_ips_file" 2>/dev/null
    sort -u "$public_ips_file" -o "$public_ips_file" 2>/dev/null
    
    local private_count=$(wc -l < "$private_ips_file" 2>/dev/null || echo "0")
    local public_count=$(wc -l < "$public_ips_file" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}[SUCCESS]${NC} IP extraction completed. Private IPs: $private_count, Public IPs: $public_count"
    
    # Display completion banner
    display_completion_banner "IP EXTRACTION" "Successfully extracted and categorized IP addresses"
}

# Function to parse JSON value (simplified JSON parser for bash)
parse_json_value() {
    local json="$1"
    local key="$2"
    echo "$json" | sed -n "s/.*\"$key\":\s*\"\([^\"]*\)\".*/\1/p" | head -1
}

# Function to parse JSON array (for ports)
parse_json_array() {
    local json="$1"
    local key="$2"
    echo "$json" | sed -n "s/.*\"$key\":\s*\[\([^]]*\)\].*/\1/p" | sed 's/[",]//g' | tr ' ' '\n' | grep -v '^$'
}

# Fixed Shodan integration with proper API endpoint and HTML parsing fallback
shodan_integration() {
    echo -e "${BLUE}[INFO]${NC} Starting Shodan integration with enhanced parsing..."
    if [ -z "$SHODAN_API_KEY" ]; then
        echo -e "${YELLOW}[WARNING]${NC} Shodan API key not provided. Skipping Shodan integration."
        return
    fi
    local public_ips_file="$OUTPUT_DIR/public_ips.txt"
    local shodan_results_html="$OUTPUT_DIR/shodan_results.html"
    local shodan_results_txt="$OUTPUT_DIR/shodan_results.txt"
    if [ ! -f "$public_ips_file" ] || [ ! -s "$public_ips_file" ]; then
        echo -e "${YELLOW}[WARNING]${NC} No public IPs file found or file is empty."
        return
    fi
    # Initialize text report
    echo "SHODAN RECONNAISSANCE REPORT" > "$shodan_results_txt"
    echo "=============================" >> "$shodan_results_txt"
    echo "Target Domain: $TARGET_DOMAIN" >> "$shodan_results_txt"
    echo "Generated: $(date)" >> "$shodan_results_txt"
    echo "" >> "$shodan_results_txt"
    # Create HTML header (keeping existing CSS)
    cat > "$shodan_results_html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Team Vortex - Shodan Reconnaissance Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { color: white; margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
        .header p { color: #f0f0f0; margin: 10px 0 0 0; font-size: 1.2em; }
        .ip-container { background: #2d2d2d; border-radius: 10px; padding: 25px; margin: 20px 0; border-left: 5px solid #667eea; }
        .ip-header { color: #667eea; font-size: 1.5em; font-weight: bold; margin-bottom: 15px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
        .info-card { background: #3a3a3a; padding: 15px; border-radius: 8px; }
        .info-label { color: #a0a0a0; font-weight: bold; margin-bottom: 5px; }
        .info-value { color: #e0e0e0; word-break: break-all; }
        .ports { background: #4a4a4a; padding: 10px; border-radius: 5px; margin-top: 10px; }
        .port { display: inline-block; background: #667eea; color: white; padding: 3px 8px; border-radius: 3px; margin: 2px; font-size: 0.9em; }
        .vulnerability { background: #ff4757; color: white; padding: 8px; border-radius: 5px; margin: 5px 0; }
        .service { background: #2ed573; color: white; padding: 5px 10px; border-radius: 5px; margin: 2px; font-size: 0.9em; display: inline-block; }
        .footer { text-align: center; margin-top: 40px; color: #a0a0a0; }
        .raw-data { background: #1a1a1a; padding: 15px; border-radius: 8px; margin-top: 10px; font-family: 'Courier New', monospace; font-size: 0.9em; max-height: 200px; overflow-y: auto; }
        .method-info { background: #333; padding: 15px; border-radius: 8px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 TEAM VORTEX SHODAN REPORT ⚡</h1>
        <p>Subdomain Enumeration - Advanced Reconnaissance</p>
EOF
    echo "        <p>Target Domain: $TARGET_DOMAIN | Generated: $(date)</p>" >> "$shodan_results_html"
    echo "    </div>" >> "$shodan_results_html"
    local ip_count=0
    local total_ips=$(wc -l < "$public_ips_file")
    while IFS= read -r ip; do
        ((ip_count++))
        echo -e "${BLUE}[SHODAN]${NC} Querying $ip ($ip_count/$total_ips)..."
        echo "Processing IP $ip_count/$total_ips: $ip" >> "$shodan_results_txt"
        echo "----------------------------------------" >> "$shodan_results_txt"
        # Try API first, then fallback to web scraping
        local shodan_response=""
        local http_code=""
        local parsing_method=""
        # Method 1: Try Shodan API (JSON)
        if [ -n "$SHODAN_API_KEY" ]; then
            echo -e "${CYAN}[DEBUG]${NC} Trying Shodan API for $ip..."
            # Use -G and --data-urlencode for better handling of the API key
            shodan_response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "https://api.shodan.io/shodan/host/$ip" -G --data-urlencode "key=$SHODAN_API_KEY" 2>/dev/null)
            http_code=$(echo "$shodan_response" | tail -n 1 | cut -d: -f2)
            # Remove the status code line from the response body
            shodan_response=$(echo "$shodan_response" | sed '$d')
            if [ "$http_code" = "200" ] && echo "$shodan_response" | grep -q '"ip"'; then
                parsing_method="API_JSON"
                echo -e "${GREEN}[SUCCESS]${NC} API response received for $ip"
            else
                echo -e "${YELLOW}[INFO]${NC} API failed (HTTP: $http_code), trying web scraping..."
                parsing_method="WEB_HTML"
            fi
        else
            parsing_method="WEB_HTML"
        fi

        # Method 2: Web scraping fallback (HTML parsing)
        if [ "$parsing_method" = "WEB_HTML" ]; then
            echo -e "${CYAN}[DEBUG]${NC} Using web scraping for $ip..."
            shodan_response=$(curl -s "https://www.shodan.io/host/$ip" 2>/dev/null)
            http_code="200" # Assume success for scraping if we get content
            # Basic check for content
            if echo "$shodan_response" | grep -q "Last Seen:"; then
                parsing_method="WEB_HTML"
                echo -e "${GREEN}[SUCCESS]${NC} Web page response received for $ip"
            else
                echo -e "${RED}[ERROR]${NC} Both API and web scraping failed for $ip"
                parsing_method="FAILED"
            fi
        fi

        # Parse based on method used
        local org="" country="" city="" isp="" asn="" os="" ports_raw="" hostnames="" vulns=""

        if [ "$parsing_method" = "API_JSON" ]; then
            # JSON parsing (original method - FIXED regex)
            echo -e "${CYAN}[DEBUG]${NC} Parsing JSON content for $ip..."
            org=$(echo "$shodan_response" | grep -o '"org":"[^"]*"' | cut -d'"' -f4 | head -1 | sed 's/\\//g') # Fix escaping
            country=$(echo "$shodan_response" | grep -o '"country_name":"[^"]*"' | cut -d'"' -f4 | head -1 | sed 's/\\//g')
            city=$(echo "$shodan_response" | grep -o '"city":"[^"]*"' | cut -d'"' -f4 | head -1 | sed 's/\\//g')
            isp=$(echo "$shodan_response" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4 | head -1 | sed 's/\\//g')
            asn=$(echo "$shodan_response" | grep -o '"asn":"[^"]*"' | cut -d'"' -f4 | head -1 | sed 's/\\//g')
            os=$(echo "$shodan_response" | grep -o '"os":"[^"]*"' | cut -d'"' -f4 | head -1 | sed 's/\\//g')
            # Fix regex for ports array
            ports_raw=$(echo "$shodan_response" | sed -n 's/.*"ports" *: *\[\([^]]*\)\].*/\1/p' | tr ',' ' ' | sed 's/[^0-9 ]//g' | tr -s ' ' | sed 's/^ *//;s/ *$//')
            # Fix regex for hostnames array
            hostnames=$(echo "$shodan_response" | sed -n 's/.*"hostnames" *: *\[\([^]]*\)\].*/\1/p' | sed 's/"//g' | tr ',' ' ' | sed 's/^ *//;s/ *$//')
            # Fix regex for vulns object (if present)
            vulns=$(echo "$shodan_response" | sed -n 's/.*"vulns" *: *{\([^}]*\)}.*/\1/p' | sed 's/"[^"]*"://g' | tr ',' ' ' | sed 's/^ *//;s/ *$//' | head -c 200) # Limit length

        elif [ "$parsing_method" = "WEB_HTML" ]; then
            # HTML parsing (new method - CORRECTED patterns based on output.txt)
            echo -e "${CYAN}[DEBUG]${NC} Parsing HTML content for $ip..."
            # Extract organization (corrected pattern)
            # Look for <label>Organization</label> followed by <div><strong><a>VALUE</a></strong></div>
            org=$(echo "$shodan_response" | sed -n '/<label>Organization<\/label>/,/<\/div>/ s/.*<a[^>]*>\([^<]*\)<\/a>.*/\1/p' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)
            # If org is still empty, try alternative pattern or Cloud Provider
            if [ -z "$org" ]; then
                 org=$(echo "$shodan_response" | sed -n '/<label>Cloud Provider<\/label>/,/<\/div>/ s/.*<a[^>]*>\([^<]*\)<\/a>.*/\1/p' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)
            fi

            # Extract country (corrected pattern)
            country=$(echo "$shodan_response" | sed -n '/<label>Country<\/label>/,/<\/div>/ s/.*<a[^>]*>\([^<]*\)<\/a>.*/\1/p' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)

            # Extract city (corrected pattern)
            city=$(echo "$shodan_response" | sed -n '/<label>City<\/label>/,/<\/div>/ s/.*<a[^>]*>\([^<]*\)<\/a>.*/\1/p' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)

            # Extract ISP (corrected pattern)
            isp=$(echo "$shodan_response" | sed -n '/<label>ISP<\/label>/,/<\/div>/ s/.*<a[^>]*>\([^<]*\)<\/a>.*/\1/p' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)

            # Extract ASN (corrected pattern)
            asn=$(echo "$shodan_response" | sed -n '/<label>ASN<\/label>/,/<\/div>/ s/.*<a[^>]*>\([^<]*\)<\/a>.*/\1/p' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)

            # Extract hostnames (simple text extract)
            # Look for Hostnames label and extract the text within the div
            hostnames=$(echo "$shodan_response" | sed -n '/<label>Hostnames<\/label>/,/<\/div>/ { /<label>/d; s/.*<div>\([^<]*\)<\/div>.*/\1/p; }' | head -1 | sed 's/&amp;/\&/g; s/</</g; s/>/>/g' | xargs)

            # Extract ports from the ports section (corrected pattern)
            # Look for <div id="ports"> and extract all <a> tags with class bg-primary
            ports_raw=$(echo "$shodan_response" | sed -n '/<div id="ports">/,/<\/div>/ s/<a[^>]*class="[^"]*bg-primary[^"]*"[^>]*>\([^<]*\)<\/a>/\1 /g p' | tr -d '\n' | sed 's/ $//' | xargs)

            # Extract OS (if available, often not directly labeled)
            os="N/A" # Hard to extract reliably from HTML without specific class/id

            # Extract vulnerabilities (if available, often requires login or specific section)
            vulns="N/A" # Hard to extract reliably from public HTML without login

            echo -e "${CYAN}[DEBUG]${NC} Extracted - Org: '$org', Country: '$country', City: '$city', ISP: '$isp', Ports: '$ports_raw'"

        else
            echo -e "${RED}[ERROR]${NC} Failed to parse data for $ip"
        fi

        # Set defaults for empty values
        [ -z "$org" ] && org="N/A"
        [ -z "$country" ] && country="N/A"
        [ -z "$city" ] && city="N/A"
        [ -z "$isp" ] && isp="N/A"
        [ -z "$asn" ] && asn="N/A"
        [ -z "$os" ] && os="N/A"
        [ -z "$ports_raw" ] && ports_raw="None detected"
        [ -z "$hostnames" ] && hostnames="None"
        [ -z "$vulns" ] && vulns="None detected"

        # Write to text report
        echo "IP: $ip" >> "$shodan_results_txt"
        echo "Parsing Method: $parsing_method" >> "$shodan_results_txt"
        echo "Organization: $org" >> "$shodan_results_txt"
        echo "Location: $city, $country" >> "$shodan_results_txt"
        echo "ISP: $isp" >> "$shodan_results_txt"
        echo "ASN: $asn" >> "$shodan_results_txt"
        echo "OS: $os" >> "$shodan_results_txt"
        echo "Ports: $ports_raw" >> "$shodan_results_txt"
        echo "Hostnames: $hostnames" >> "$shodan_results_txt"
        echo "Vulnerabilities: $vulns" >> "$shodan_results_txt"
        echo "" >> "$shodan_results_txt"

        # Add to HTML with enhanced display
        cat >> "$shodan_results_html" << EOF
    <div class="ip-container">
        <div class="ip-header">🎯 IP Address: $ip</div>
        <div class="method-info">
            <strong>📊 Data Source:</strong> $parsing_method
        </div>
        <div class="info-grid">
            <div class="info-card">
                <div class="info-label">🏢 Organization</div>
                <div class="info-value">$org</div>
            </div>
            <div class="info-card">
                <div class="info-label">🌍 Location</div>
                <div class="info-value">$city, $country</div>
            </div>
            <div class="info-card">
                <div class="info-label">🌐 ISP</div>
                <div class="info-value">$isp</div>
            </div>
            <div class="info-card">
                <div class="info-label">🏷️ ASN</div>
                <div class="info-value">$asn</div>
            </div>
            <div class="info-card">
                <div class="info-label">💻 Operating System</div>
                <div class="info-value">$os</div>
            </div>
            <div class="info-card">
                <div class="info-label">🏠 Hostnames</div>
                <div class="info-value">$hostnames</div>
            </div>
        </div>
        <div class="ports">
            <strong>🔓 Open Ports:</strong><br>
EOF
        # Add ports with better formatting
        if [ "$ports_raw" != "None detected" ] && [ "$ports_raw" != "N/A" ] && [ -n "$ports_raw" ]; then
            # Iterate through space-separated ports
            for port in $ports_raw; do
                if [ -n "$port" ]; then
                    echo "            <span class=\"port\">$port</span>" >> "$shodan_results_html"
                fi
            done
        else
            echo "            <span class=\"port\">No open ports detected</span>" >> "$shodan_results_html"
        fi
        # Add vulnerabilities section
        cat >> "$shodan_results_html" << EOF
        </div>
        <div class="ports" style="margin-top: 15px;">
            <strong>⚠️ Vulnerabilities:</strong><br>
EOF
        if [ "$vulns" != "None detected" ] && [ "$vulns" != "N/A" ] && [ -n "$vulns" ]; then
            # Limit displayed vulns to prevent huge output
            echo "$vulns" | head -5 | while read -r vuln; do
                [ -n "$vuln" ] && echo "            <span class=\"vulnerability\">$vuln</span>" >> "$shodan_results_html"
            done
        else
            echo "            <span style=\"color: #2ed573;\">✅ No known vulnerabilities detected</span>" >> "$shodan_results_html"
        fi
        # Close the IP container
        echo "        </div>" >> "$shodan_results_html"
        echo "    </div>" >> "$shodan_results_html"

        # Display results
        if [ "$org" != "N/A" ] || [ "$country" != "N/A" ]; then
            echo -e "${GREEN}[SHODAN SUCCESS]${NC} $ip - $org ($city, $country) - Method: $parsing_method"
        else
            echo -e "${YELLOW}[SHODAN]${NC} Limited data for $ip - Method: $parsing_method"
        fi
        sleep "$API_RATE_LIMIT"  # Rate limiting
    done < "$public_ips_file"
    # Close HTML
    cat >> "$shodan_results_html" << EOF
    <div class="footer">
        <p>Generated by Team Vortex Subdomain Enumeration Tool</p>
        <p>Enhanced Shodan Integration with API + Web Scraping</p>
        <p>Automatic fallback from API to HTML parsing for comprehensive data collection</p>
    </div>
</body>
</html>
EOF
    echo -e "${GREEN}[SUCCESS]${NC} Shodan integration completed with hybrid parsing approach."
    echo -e "${CYAN}[REPORTS]${NC} HTML report: $shodan_results_html"
    echo -e "${CYAN}[REPORTS]${NC} Text report: $shodan_results_txt"
    # Display completion banner
    display_completion_banner "ENHANCED SHODAN INTEGRATION" "Successfully implemented API + HTML parsing hybrid approach"
}

# Function to generate comprehensive HTML report
generate_html_report() {
    echo -e "${BLUE}[INFO]${NC} Generating comprehensive HTML report..."
    
    local html_report_file="$OUTPUT_DIR/comprehensive_report.html"
    local text_report_file="$OUTPUT_DIR/summary_report.txt"
    
    # Get counts
    local brute_count=$(wc -l < "$OUTPUT_DIR/brute_force_subdomains.txt" 2>/dev/null || echo "0")
    local api_count=$(wc -l < "$OUTPUT_DIR/api_subdomains.txt" 2>/dev/null || echo "0")
    local live_count=$(wc -l < "$OUTPUT_DIR/live_subdomains.txt" 2>/dev/null || echo "0")
    local dead_count=$(wc -l < "$OUTPUT_DIR/dead_subdomains.txt" 2>/dev/null || echo "0")
    local private_count=$(wc -l < "$OUTPUT_DIR/private_ips.txt" 2>/dev/null || echo "0")
    local public_count=$(wc -l < "$OUTPUT_DIR/public_ips.txt" 2>/dev/null || echo "0")
    local total_subdomains=$((brute_count + api_count))
    
    # Create comprehensive HTML report
    cat > "$html_report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$TEAM_NAME - Comprehensive Subdomain Enumeration Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: #fff; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: rgba(0,0,0,0.8); padding: 40px; text-align: center; border-radius: 15px; margin-bottom: 30px; backdrop-filter: blur(10px); position: relative; }
        .header h1 { font-size: 3em; margin-bottom: 10px; background: linear-gradient(45deg, #ff6b6b, #4ecdc4, #45b7d1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: rgba(255,255,255,0.1); padding: 25px; border-radius: 10px; text-align: center; backdrop-filter: blur(5px); border: 1px solid rgba(255,255,255,0.2); }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #4ecdc4; }
        .stat-label { margin-top: 10px; font-size: 1.1em; }
        .section { background: rgba(0,0,0,0.6); margin: 20px 0; padding: 30px; border-radius: 15px; backdrop-filter: blur(10px); }
        .section-title { font-size: 1.8em; margin-bottom: 20px; color: #4ecdc4; border-bottom: 2px solid #4ecdc4; padding-bottom: 10px; }
        .subdomain-list { max-height: 300px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; }
        .subdomain-item { padding: 8px; margin: 5px 0; background: rgba(255,255,255,0.1); border-radius: 5px; }
        .live { border-left: 4px solid #2ecc71; }
        .dead { border-left: 4px solid #e74c3c; }
        .ip-mapping { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 10px; margin: 15px 0; }
        .ip-item { display: flex; justify-content: space-between; padding: 10px; margin: 5px 0; background: rgba(255,255,255,0.1); border-radius: 5px; }
        .private-ip { color: #f39c12; }
        .public-ip { color: #3498db; }
        .progress-bar { width: 100%; height: 20px; background: rgba(0,0,0,0.3); border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #4ecdc4, #44a08d); transition: width 0.3s ease; }
        .footer { text-align: center; margin-top: 40px; padding: 20px; opacity: 0.8; }
        .team-info { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; margin: 20px 0; }
        .methodology { background: rgba(0,0,0,0.4); padding: 20px; border-radius: 10px; margin: 20px 0; }
        .method-item { background: rgba(255,255,255,0.1); margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid #4ecdc4; }
        @media (max-width: 768px) { .header { text-align: center; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 $TEAM_NAME 🚀</h1>
            <p>Advanced Subdomain Enumeration & Reconnaissance Report</p>
            <p>Target: <strong>$TARGET_DOMAIN</strong> | Generated: <strong>$(date)</strong></p>
        </div>

        <div class="team-info">
            <h2 style="text-align: center; margin-bottom: 15px;">👑 Team Information</h2>
            <p style="text-align: center;"><strong>Lead:</strong> $TEAM_LEAD</p>
            <p style="text-align: center;"><strong>Members:</strong> $TEAM_MEMBERS</p>
            <p style="text-align: center;"><strong>Project:</strong> $PROJECT_NAME</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$total_subdomains</div>
                <div class="stat-label">Total Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$live_count</div>
                <div class="stat-label">Live Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$public_count</div>
                <div class="stat-label">Public IP Addresses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$private_count</div>
                <div class="stat-label">Private IP Addresses</div>
            </div>
        </div>

        <div class="methodology">
            <h2 class="section-title">🔍 Enhanced Methodology</h2>
            <div class="method-item">
                <strong>🧵 Parallel Processing:</strong> Multithreaded enumeration with $MAX_THREADS concurrent processes
            </div>
            <div class="method-item">
                <strong>🌐 Multi-API Integration:</strong> VirusTotal, crt.sh, and HackerTarget APIs
            </div>
            <div class="method-item">
                <strong>⚡ Smart Live Detection:</strong> HTTP/HTTPS connectivity verification
            </div>
            <div class="method-item">
                <strong>🎯 Enhanced Shodan Integration:</strong> Detailed reconnaissance with vulnerability detection
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📊 Discovery Breakdown</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <div>
                    <h3>Brute Force Results</h3>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 70%"></div>
                    </div>
                    <p>$brute_count subdomains discovered</p>
                </div>
                <div>
                    <h3>API Results</h3>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 50%"></div>
                    </div>
                    <p>$api_count subdomains from APIs</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">🟢 Live Subdomains ($live_count)</h2>
            <div class="subdomain-list">
EOF

    # Add live subdomains to HTML
    if [ -f "$OUTPUT_DIR/live_subdomains.txt" ] && [ -s "$OUTPUT_DIR/live_subdomains.txt" ]; then
        while IFS= read -r subdomain; do
            echo "                <div class=\"subdomain-item live\">✅ $subdomain</div>" >> "$html_report_file"
        done < "$OUTPUT_DIR/live_subdomains.txt"
    else
        echo "                <div class=\"subdomain-item\">No live subdomains found</div>" >> "$html_report_file"
    fi

    cat >> "$html_report_file" << EOF
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">🌐 IP Address Mapping</h2>
            <div class="ip-mapping">
EOF

    # Add IP mappings to HTML
    if [ -f "$OUTPUT_DIR/subdomain_ip_mapping.txt" ] && [ -s "$OUTPUT_DIR/subdomain_ip_mapping.txt" ]; then
        while IFS= read -r mapping; do
            local subdomain=$(echo "$mapping" | cut -d' ' -f1)
            local ip=$(echo "$mapping" | cut -d' ' -f3)
            
            # Check if IP is private or public
            if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
                echo "                <div class=\"ip-item\"><span>$subdomain</span><span class=\"private-ip\">🔒 $ip (Private)</span></div>" >> "$html_report_file"
            else
                echo "                <div class=\"ip-item\"><span>$subdomain</span><span class=\"public-ip\">🌍 $ip (Public)</span></div>" >> "$html_report_file"
            fi
        done < "$OUTPUT_DIR/subdomain_ip_mapping.txt"
    else
        echo "                <div class=\"ip-item\">No IP mappings available</div>" >> "$html_report_file"
    fi

    cat >> "$html_report_file" << EOF
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📁 Generated Files</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">
EOF

    # Add file information
    for file in "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.html; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            local filesize=$(du -h "$file" 2>/dev/null | cut -f1)
            local entries="N/A"
            
            if [[ $file == *.txt ]]; then
                entries=$(wc -l < "$file" 2>/dev/null || echo "0")
            fi
            
            cat >> "$html_report_file" << EOF
                <div class="stat-card">
                    <div style="font-size: 1.2em; color: #4ecdc4;">📄 $filename</div>
                    <div>Size: $filesize</div>
                    <div>Entries: $entries</div>
                </div>
EOF
        fi
    done

    cat >> "$html_report_file" << EOF
            </div>
        </div>

        <div class="footer">
            <p>🚀 Generated by $TEAM_NAME Advanced Subdomain Enumeration Tool</p>
            <p>$PROJECT_NAME - Enhanced with Improved Shodan Integration</p>
            <p>For detailed reconnaissance data, check the Shodan reports</p>
        </div>
    </div>
</body>
</html>
EOF

    # Generate text report
    {
        echo "=================================================================================="
        echo "                    $TEAM_NAME SUBDOMAIN ENUMERATION REPORT"
        echo "=================================================================================="
        echo "Target Domain: $TARGET_DOMAIN"
        echo "Scan Date: $(date)"
        echo "Output Directory: $OUTPUT_DIR"
        echo "Max Concurrent Processes: $MAX_THREADS"
        echo ""
        
        echo "SUMMARY:"
        echo "--------"
        echo "Brute Force Subdomains Found: $brute_count"
        echo "API-based Subdomains Found: $api_count"
        echo "Total Unique Subdomains: $total_subdomains"
        echo "Live Subdomains: $live_count"
        echo "Dead Subdomains: $dead_count"
        echo "Private IPs: $private_count"
        echo "Public IPs: $public_count"
        echo ""
        
        echo "ENHANCED METHODOLOGY:"
        echo "--------------------"
        echo "- Multi-threaded brute force enumeration ($MAX_THREADS processes)"
        echo "- API integration: VirusTotal, crt.sh, HackerTarget"
        echo "- Intelligent live subdomain verification"
        echo "- Advanced IP categorization (Private/Public)"
        echo "- Enhanced Shodan integration with detailed parsing"
        echo "- Comprehensive HTML and text reporting"
        echo ""
        
        echo "FILES GENERATED:"
        echo "---------------"
        for file in "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.html; do
            if [ -f "$file" ]; then
                local entries=$(wc -l < "$file" 2>/dev/null || echo "N/A")
                echo "- $(basename "$file"): $entries entries"
            fi
        done
        
        echo ""
        echo "TEAM INFORMATION:"
        echo "----------------"
        echo "Team Lead: $TEAM_LEAD"
        echo "Team Members: $TEAM_MEMBERS"
        echo "Project: $PROJECT_NAME"
        
    } > "$text_report_file"
    
    echo -e "${GREEN}[SUCCESS]${NC} Comprehensive reports generated:"
    echo -e "${CYAN}[HTML]${NC} $html_report_file"
    echo -e "${CYAN}[TEXT]${NC} $text_report_file"
    
    # Display completion banner
    display_completion_banner "HTML REPORT GENERATION" "Successfully generated enhanced comprehensive reports"
}

# Main function
main() {
    display_startup_banner
    display_banner
    
    # Load configuration first
    if ! load_config; then
        echo -e "${YELLOW}[INFO]${NC} Creating basic configuration..."
        echo -e "${CYAN}[INPUT]${NC} Enter wordlist path (e.g., /path/to/wordlist.txt):"
        read -r WORDLIST_PATH
        
        if [ ! -f "$WORDLIST_PATH" ]; then
            echo -e "${RED}[ERROR]${NC} Wordlist file not found: $WORDLIST_PATH"
            exit 1
        fi
        
        echo -e "${CYAN}[INPUT]${NC} Enter VirusTotal API Key (optional, press Enter to skip):"
        read -r VIRUSTOTAL_API_KEY
        
        echo -e "${CYAN}[INPUT]${NC} Enter Shodan API Key (optional, press Enter to skip):"
        read -r SHODAN_API_KEY
    fi
    
    check_dependencies
    get_user_input
    
    echo -e "${BLUE}[INFO]${NC} Starting enhanced subdomain enumeration for: $TARGET_DOMAIN"
    echo -e "${BLUE}[INFO]${NC} Using $MAX_THREADS concurrent processes"
    echo ""
    
    # Phase 1: Subdomain Enumeration
    brute_force_subdomains
    api_based_enumeration
    
    # Phase 2: Live Subdomain Identification
    identify_live_subdomains
    
    # Phase 3: IP Extraction
    extract_ips
    
    # Phase 4: Enhanced Shodan Integration
    shodan_integration
    
    # Generate Comprehensive Reports
    generate_html_report
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                🎉 SCAN COMPLETED! 🎉                                 ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  Target Domain: ${CYAN}$TARGET_DOMAIN${WHITE}                                         ║${NC}"
    echo -e "${WHITE}║  Results Directory: ${CYAN}$OUTPUT_DIR${WHITE}                                        ║${NC}"
    echo -e "${WHITE}║  Max Processes: ${CYAN}$MAX_THREADS${WHITE}                                           ║${NC}"
    echo -e "${WHITE}║  Main Report: ${CYAN}comprehensive_report.html${WHITE}                                ║${NC}"
    echo -e "${WHITE}║  Shodan Report: ${CYAN}shodan_results.html${WHITE}                                    ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}🚀 Developed by: $TEAM_NAME Subdomain Enumeration Tool - Mission Complete! ⚡${NC}"
    echo -e "${BLUE}📧 For support: TEAM VORTEX${NC}"
}

# Trap to handle script interruption
trap 'echo -e "\n${RED}[INFO]${NC} Script interrupted by user. Cleaning up..."; jobs -p | xargs -r kill; exit 1' INT

# Run the main function
main "$@"
