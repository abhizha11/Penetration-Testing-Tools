#!/bin/bash
#
# BugHunter Recon Suite - Professional Bug Bounty Reconnaissance Tool
# Advanced reconnaissance automation for bug bounty hunters
# Author: Security Research Team
# Version: 2.0
#

set -euo pipefail

# Ensure Go-installed binaries are reachable regardless of how the script is invoked
for _gobin in \
    "$HOME/go/bin" \
    "/root/go/bin" \
    "/home/$USER/go/bin" \
    "$(go env GOPATH 2>/dev/null)/bin" \
    "/usr/local/go/bin"; do
    [ -d "$_gobin" ] && PATH="$_gobin:$PATH" || true
done
export PATH

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
TARGET=""
OUTPUT_DIR="./recon_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR=""
THREADS=50
RATE_LIMIT=1000
TIMEOUT=10
VERBOSE=false
QUICK_MODE=false

# Tool availability flags
HAVE_NSLOOKUP=false
HAVE_DIG=false
HAVE_WHOIS=false
HAVE_CURL=false
HAVE_WGET=false
HAVE_NMAP=false
HAVE_SUBFINDER=false
HAVE_AMASS=false
HAVE_ASSETFINDER=false
HAVE_HTTPX=false
HAVE_NUCLEI=false
HAVE_WAYBACKURLS=false
HAVE_GAU=false
HAVE_FFUF=false
HAVE_FEROXBUSTER=false
HAVE_WHATWEB=false
HAVE_NIKTO=false
HAVE_GOBUSTER=false
HAVE_DNSRECON=false
HAVE_MASSCAN=false
HAVE_JQ=false
HAVE_ANEW=false
HTTPX_BIN=""

strip_ansi_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$file" > "${file}.clean" 2>/dev/null || return 0
    mv "${file}.clean" "$file"
}

write_no_results_note() {
    local file="$1"
    local note="$2"
    if [ ! -s "$file" ]; then
        printf '%s\n' "$note" > "$file"
    fi
}

resolve_httpx_bin() {
    local candidate=""
    local gobin_httpx="$(go env GOPATH 2>/dev/null)/bin/httpx"
    local candidates=(
        "$HOME/go/bin/httpx"
        "/root/go/bin/httpx"
        "$gobin_httpx"
        "$(command -v httpx 2>/dev/null || true)"
    )

    for candidate in "${candidates[@]}"; do
        [ -n "$candidate" ] || continue
        [ -x "$candidate" ] || continue
        if "$candidate" -h 2>&1 | grep -q -- '-silent'; then
            HTTPX_BIN="$candidate"
            return 0
        fi
    done

    HTTPX_BIN=""
    return 1
}

# Function to print colored output
print_header() {
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC} ${CYAN}$1${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
}

print_subheader() {
    echo -e "\n${MAGENTA}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

# Banner
show_banner() {
    echo -e "${RED}"
    cat << "BANNER"
    ____             __  __            __            
   / __ )__  ______ / / / /_  ______  / /____  _____ 
  / __  / / / / __ / /_/ / / / / __ \/ __/ _ \/ ___/
 / /_/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /    
/_____/\__,_/\__, /_/ /_/\__,_/_/ /_/\__/\___/_/     
            /____/                                    
    ____                          _____       _ __      
   / __ \___  _________  ____    / ___/__  __(_) /____  
  / /_/ / _ \/ ___/ __ \/ __ \   \__ \/ / / / / __/ _ \ 
 / _, _/  __/ /__/ /_/ / / / /  ___/ / /_/ / / /_/  __/ 
/_/ |_|\___/\___/\____/_/ /_/  /____/\__,_/_/\__/\___/  
                                                        
BANNER
    echo -e "${NC}"
    echo -e "${CYAN}  Professional Bug Bounty Reconnaissance Suite v2.0${NC}"
    echo -e "${YELLOW}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Check if required tools are available
check_tools() {
    print_header "Checking Available Tools"
    
    local tools_found=0
    local tools_missing=0
    
    echo ""
    print_subheader "Core DNS Tools"
    
    if command -v nslookup &> /dev/null; then
        HAVE_NSLOOKUP=true
        print_success "nslookup"
        ((tools_found+=1)) || true
    else
        print_error "nslookup (install: dnsutils)"
        ((tools_missing+=1)) || true
    fi
    
    if command -v dig &> /dev/null; then
        HAVE_DIG=true
        print_success "dig"
        ((tools_found+=1)) || true
    else
        print_error "dig (install: dnsutils)"
        ((tools_missing+=1)) || true
    fi
    
    if command -v dnsrecon &> /dev/null; then
        HAVE_DNSRECON=true
        print_success "dnsrecon"
        ((tools_found+=1)) || true
    else
        print_warning "dnsrecon (pip install dnsrecon)"
        ((tools_missing+=1)) || true
    fi
    
    print_subheader "OSINT Tools"
    
    if command -v whois &> /dev/null; then
        HAVE_WHOIS=true
        print_success "whois"
        ((tools_found+=1)) || true
    else
        print_error "whois"
        ((tools_missing+=1)) || true
    fi
    
    if command -v curl &> /dev/null; then
        HAVE_CURL=true
        print_success "curl"
        ((tools_found+=1)) || true
    else
        print_error "curl"
        ((tools_missing+=1)) || true
    fi
    
    if command -v wget &> /dev/null; then
        HAVE_WGET=true
        print_success "wget"
        ((tools_found+=1)) || true
    fi
    
    if command -v jq &> /dev/null; then
        HAVE_JQ=true
        print_success "jq"
        ((tools_found+=1)) || true
    else
        print_warning "jq (apt install jq)"
    fi
    
    print_subheader "Subdomain Enumeration"
    
    if command -v subfinder &> /dev/null; then
        HAVE_SUBFINDER=true
        print_success "subfinder"
        ((tools_found+=1)) || true
    else
        print_warning "subfinder (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
    fi
    
    if command -v amass &> /dev/null; then
        HAVE_AMASS=true
        print_success "amass"
        ((tools_found+=1)) || true
    else
        print_warning "amass (go install -v github.com/owasp-amass/amass/v4/...@master)"
    fi
    
    if command -v assetfinder &> /dev/null; then
        HAVE_ASSETFINDER=true
        print_success "assetfinder"
        ((tools_found+=1)) || true
    else
        print_warning "assetfinder (go install github.com/tomnomnom/assetfinder@latest)"
    fi
    
    print_subheader "HTTP Probing & Analysis"
    
    if resolve_httpx_bin; then
        HAVE_HTTPX=true
        print_success "httpx ($(basename "$HTTPX_BIN"))"
        ((tools_found+=1)) || true
    elif command -v httpx &> /dev/null; then
        print_warning "httpx found, but it is not the ProjectDiscovery binary; HTTP probing will use curl fallback"
    else
        print_warning "httpx (go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)"
    fi
    
    if command -v whatweb &> /dev/null; then
        HAVE_WHATWEB=true
        print_success "whatweb"
        ((tools_found+=1)) || true
    else
        print_warning "whatweb (apt install whatweb)"
    fi
    
    print_subheader "URL Discovery"
    
    if command -v waybackurls &> /dev/null; then
        HAVE_WAYBACKURLS=true
        print_success "waybackurls"
        ((tools_found+=1)) || true
    else
        print_warning "waybackurls (go install github.com/tomnomnom/waybackurls@latest)"
    fi
    
    if command -v gau &> /dev/null; then
        HAVE_GAU=true
        print_success "gau"
        ((tools_found+=1)) || true
    else
        print_warning "gau (go install github.com/lc/gau/v2/cmd/gau@latest)"
    fi
    
    print_subheader "Port Scanning"
    
    if command -v nmap &> /dev/null; then
        HAVE_NMAP=true
        print_success "nmap"
        ((tools_found+=1)) || true
    else
        print_warning "nmap (apt install nmap)"
    fi
    
    if command -v masscan &> /dev/null; then
        HAVE_MASSCAN=true
        print_success "masscan"
        ((tools_found+=1)) || true
    else
        print_warning "masscan (apt install masscan)"
    fi
    
    print_subheader "Fuzzing & Directory Bruteforce"
    
    if command -v ffuf &> /dev/null; then
        HAVE_FFUF=true
        print_success "ffuf"
        ((tools_found+=1)) || true
    else
        print_warning "ffuf (go install github.com/ffuf/ffuf/v2@latest)"
    fi
    
    if command -v gobuster &> /dev/null; then
        HAVE_GOBUSTER=true
        print_success "gobuster"
        ((tools_found+=1)) || true
    else
        print_warning "gobuster (go install github.com/OJ/gobuster/v3@latest)"
    fi

    if command -v feroxbuster &> /dev/null; then
        HAVE_FEROXBUSTER=true
        print_success "feroxbuster"
        ((tools_found+=1)) || true
    else
        print_warning "feroxbuster (curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash)"
    fi
    
    print_subheader "Vulnerability Scanning"
    
    if command -v nuclei &> /dev/null; then
        HAVE_NUCLEI=true
        print_success "nuclei"
        ((tools_found+=1)) || true
    else
        print_warning "nuclei (go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
    fi
    
    if command -v nikto &> /dev/null; then
        HAVE_NIKTO=true
        print_success "nikto"
        ((tools_found+=1)) || true
    else
        print_warning "nikto (apt install nikto)"
    fi
    
    if command -v anew &> /dev/null; then
        HAVE_ANEW=true
        print_success "anew"
        ((tools_found+=1)) || true
    else
        print_warning "anew (go install github.com/tomnomnom/anew@latest)"
    fi
    
    echo ""
    print_info "Tools found: ${tools_found} | Missing optional: ${tools_missing}"
    echo ""
}

# DNS Lookup using nslookup
dns_lookup_nslookup() {
    if [ "$HAVE_NSLOOKUP" = false ]; then
        print_error "nslookup not available"
        return 1
    fi
    
    print_info "Performing DNS lookup with nslookup..."
    nslookup "$TARGET" > "${RESULTS_DIR}/01_nslookup.txt" 2>&1 || true
    print_success "Results saved to 01_nslookup.txt"
}

# DNS Lookup using dig
dns_lookup_dig() {
    if [ "$HAVE_DIG" = false ]; then
        print_error "dig not available"
        return 1
    fi
    
    local output_file="${RESULTS_DIR}/02_dig.txt"
    local record_types=(A AAAA CNAME MX NS TXT SOA CAA PTR SRV ANY)

    print_info "Running advanced DNS queries with dig..."
    : > "$output_file"

    for record_type in "${record_types[@]}"; do
        {
            echo "===== ${record_type} ====="
            dig +nocmd "$TARGET" "$record_type" +noall +answer +multiline
            echo ""
        } >> "$output_file" 2>&1 || true
    done

    {
        echo "===== TRACE ====="
        dig +trace "$TARGET"
        echo ""
        echo "===== DNSKEY ====="
        dig "$TARGET" DNSKEY +noall +answer
        echo ""
        echo "===== DMARC ====="
        dig _dmarc."$TARGET" TXT +noall +answer
        echo ""
        echo "===== SPF ====="
        dig "$TARGET" TXT +noall +answer | grep -i "spf" || true
        echo ""
    } >> "$output_file" 2>&1 || true

    print_success "Results saved to 02_dig.txt"
}

# Advanced DNS reconnaissance
dns_deep_recon() {
    if [ "$HAVE_DNSRECON" = false ]; then
        print_warning "dnsrecon not available, skipping deep DNS reconnaissance"
        return 0
    fi

    print_info "Running deep DNS reconnaissance with dnsrecon..."
    dnsrecon -d "$TARGET" -t std,brt,srv,zonewalk > "${RESULTS_DIR}/03_dnsrecon.txt" 2>&1 || true
    print_success "Results saved to 03_dnsrecon.txt"
}

# WHOIS lookup
whois_lookup() {
    if [ "$HAVE_WHOIS" = false ]; then
        print_error "whois not available"
        return 1
    fi
    
    print_info "Performing WHOIS lookup..."
    whois "$TARGET" > "${RESULTS_DIR}/04_whois.txt" 2>&1 || true
    print_success "Results saved to 04_whois.txt"
}

# HTTP/HTTPS Header Analysis with curl
curl_headers() {
    if [ "$HAVE_CURL" = false ]; then
        print_error "curl not available"
        return 1
    fi
    
    print_info "Analyzing HTTP headers with curl (HTTP)..."
    curl -skI --connect-timeout "$TIMEOUT" -A "Mozilla/5.0" "http://${TARGET}" > "${RESULTS_DIR}/05_curl_http.txt" 2>&1 || true
    print_success "Results saved to 05_curl_http.txt"
    
    print_info "Analyzing HTTP headers with curl (HTTPS)..."
    curl -skI --connect-timeout "$TIMEOUT" -A "Mozilla/5.0" "https://${TARGET}" > "${RESULTS_DIR}/06_curl_https.txt" 2>&1 || true
    curl -skL --connect-timeout "$TIMEOUT" -A "Mozilla/5.0" -D - "https://${TARGET}" -o /dev/null >> "${RESULTS_DIR}/06_curl_https.txt" 2>&1 || true
    print_success "Results saved to 06_curl_https.txt"
}

# Active HTTP probing
http_probe() {
    local output_file="${RESULTS_DIR}/07_httpx.txt"

    if [ "$HAVE_HTTPX" = true ] && [ -n "$HTTPX_BIN" ]; then
        print_info "Probing web services with httpx..."
        printf '%s\n' "$TARGET" | "$HTTPX_BIN" -silent -status-code -title -tech-detect -follow-redirects -timeout "$TIMEOUT" -rate-limit "$RATE_LIMIT" > "$output_file" 2>&1 || true
        write_no_results_note "$output_file" "No httpx findings returned for ${TARGET}."
        print_success "Results saved to 07_httpx.txt"
        return 0
    fi

    print_warning "ProjectDiscovery httpx not available; using curl fallback probe"
    {
        echo "Fallback probe used because ProjectDiscovery httpx was not found on PATH."
        echo "===== HTTPS ====="
        curl -skI --connect-timeout "$TIMEOUT" -A "Mozilla/5.0" "https://${TARGET}" || true
        echo ""
        echo "===== HTTPS Redirect Chain ====="
        curl -skL --connect-timeout "$TIMEOUT" -A "Mozilla/5.0" -D - "https://${TARGET}" -o /dev/null || true
        echo ""
        echo "===== HTTP ====="
        curl -sI --connect-timeout "$TIMEOUT" -A "Mozilla/5.0" "http://${TARGET}" || true
    } > "$output_file" 2>&1
    write_no_results_note "$output_file" "No HTTP probe findings returned for ${TARGET}."
    print_success "Results saved to 07_httpx.txt"
}

# Technology fingerprinting
fingerprint_web() {
    if [ "$HAVE_WHATWEB" = false ]; then
        print_warning "whatweb not available, skipping technology fingerprinting"
        return 0
    fi

    print_info "Fingerprinting web stack with whatweb..."
    : > "${RESULTS_DIR}/08_whatweb.txt"
    whatweb --no-errors -a 3 "https://${TARGET}" >> "${RESULTS_DIR}/08_whatweb.txt" 2>&1 || true
    whatweb --no-errors -a 3 "http://${TARGET}" >> "${RESULTS_DIR}/08_whatweb.txt" 2>&1 || true
    strip_ansi_file "${RESULTS_DIR}/08_whatweb.txt"
    write_no_results_note "${RESULTS_DIR}/08_whatweb.txt" "No WhatWeb fingerprinting findings returned for ${TARGET}."
    print_success "Results saved to 08_whatweb.txt"
}

# Reverse DNS lookup
reverse_dns_lookup() {
    if [ "$HAVE_DIG" = false ]; then
        print_error "dig not available"
        return 1
    fi
    
    print_info "Attempting reverse DNS lookup..."
    dig -x "$TARGET" > "${RESULTS_DIR}/09_reverse_dns.txt" 2>&1 || true
    print_success "Results saved to 09_reverse_dns.txt"
}

# Subdomain enumeration via DNS
subdomain_enum() {
    print_info "Running subdomain reconnaissance..."

    if [ "$HAVE_DIG" = true ]; then
        {
            echo "===== ZONE TRANSFER ====="
            dig @8.8.8.8 "$TARGET" AXFR
            echo ""
        } > "${RESULTS_DIR}/10_zone_transfer.txt" 2>&1 || true
        print_success "Results saved to 10_zone_transfer.txt"
    fi

    if [ "$HAVE_SUBFINDER" = true ]; then
        subfinder -d "$TARGET" -silent > "${RESULTS_DIR}/11_subfinder.txt" 2>&1 || true
        sort -u "${RESULTS_DIR}/11_subfinder.txt" -o "${RESULTS_DIR}/11_subfinder.txt" 2>/dev/null || true
        print_success "Results saved to 11_subfinder.txt"
    fi

    if [ "$HAVE_ASSETFINDER" = true ]; then
        assetfinder --subs-only "$TARGET" 2>/dev/null | grep -E "(^|\.)${TARGET}$" | sort -u > "${RESULTS_DIR}/12_assetfinder.txt" || true
        write_no_results_note "${RESULTS_DIR}/12_assetfinder.txt" "No assetfinder subdomains returned for ${TARGET}."
        print_success "Results saved to 12_assetfinder.txt"
    fi

    if [ "$HAVE_AMASS" = true ]; then
        amass enum -passive -silent -d "$TARGET" 2>/dev/null | grep -E "(^|\.)${TARGET}$" | sort -u > "${RESULTS_DIR}/13_amass.txt" || true
        write_no_results_note "${RESULTS_DIR}/13_amass.txt" "No amass subdomains returned for ${TARGET}."
        print_success "Results saved to 13_amass.txt"
    fi

    # ffuf subdomain fuzzing — DNS mode (FUZZ.TARGET) + vhost mode (Host header)
    if [ "$HAVE_FFUF" = true ]; then
        local sub_wordlist=""
        local sub_candidates=(
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
            "/usr/share/seclists/Discovery/DNS/namelist.txt"
            "/usr/share/wordlists/dnsmap.txt"
        )
        for wl in "${sub_candidates[@]}"; do
            if [ -f "$wl" ]; then
                sub_wordlist="$wl"
                break
            fi
        done

        if [ -n "$sub_wordlist" ]; then
            # Mode 1: DNS subdomain brute-force — resolves FUZZ.TARGET directly
            print_info "Running ffuf DNS subdomain fuzzing..."
            ffuf -u "https://FUZZ.${TARGET}" \
                 -w "$sub_wordlist" \
                 -mc 200,204,301,302,307,401,403 \
                 -t "$THREADS" \
                 -timeout "$TIMEOUT" \
                 -of json \
                 -o "${RESULTS_DIR}/13b_ffuf_dns_subdomains.json" \
                 -s 2>/dev/null || true
            ffuf -u "https://FUZZ.${TARGET}" \
                 -w "$sub_wordlist" \
                 -mc 200,204,301,302,307,401,403 \
                 -t "$THREADS" \
                 -timeout "$TIMEOUT" \
                 -s \
                 > "${RESULTS_DIR}/13b_ffuf_dns_subdomains.txt" 2>&1 || true
            print_success "Results saved to 13b_ffuf_dns_subdomains.txt / .json"

            # Mode 2: Virtual host fuzzing — Host header enumeration
            print_info "Running ffuf vhost subdomain fuzzing..."
            ffuf -u "https://${TARGET}" \
                 -H "Host: FUZZ.${TARGET}" \
                 -w "$sub_wordlist" \
                 -mc 200,204,301,302,307,401,403 \
                 -t "$THREADS" \
                 -timeout "$TIMEOUT" \
                 -of json \
                 -o "${RESULTS_DIR}/13c_ffuf_vhost_subdomains.json" \
                 -s 2>/dev/null || true
            ffuf -u "https://${TARGET}" \
                 -H "Host: FUZZ.${TARGET}" \
                 -w "$sub_wordlist" \
                 -mc 200,204,301,302,307,401,403 \
                 -t "$THREADS" \
                 -timeout "$TIMEOUT" \
                 -s \
                 > "${RESULTS_DIR}/13c_ffuf_vhost_subdomains.txt" 2>&1 || true
            print_success "Results saved to 13c_ffuf_vhost_subdomains.txt / .json"
        else
            print_warning "No subdomain wordlist found for ffuf. Install seclists: apt install seclists"
        fi
    fi

    # Merge & deduplicate all subdomain results with anew
    local master="${RESULTS_DIR}/00_all_subdomains.txt"
    : > "$master"
    if [ "$HAVE_ANEW" = true ]; then
        # Plain one-subdomain-per-line files
        for f in "${RESULTS_DIR}/11_subfinder.txt" \
                 "${RESULTS_DIR}/12_assetfinder.txt" \
                 "${RESULTS_DIR}/13_amass.txt"; do
            [ -s "$f" ] && cat "$f" | anew "$master" > /dev/null 2>&1 || true
        done
        # Extract subdomains from ffuf plain-text output lines
        for f in "${RESULTS_DIR}/13b_ffuf_dns_subdomains.txt" \
                 "${RESULTS_DIR}/13c_ffuf_vhost_subdomains.txt"; do
            [ -s "$f" ] && grep -oE "[a-zA-Z0-9._-]+\.${TARGET}" "$f" 2>/dev/null | anew "$master" > /dev/null 2>&1 || true
        done
        print_success "Deduplicated master subdomain list: 00_all_subdomains.txt ($(wc -l < "$master") entries)"
    else
        # Fallback: plain sort|uniq merge when anew is not installed
        for f in "${RESULTS_DIR}/11_subfinder.txt" \
                 "${RESULTS_DIR}/12_assetfinder.txt" \
                 "${RESULTS_DIR}/13_amass.txt"; do
            [ -s "$f" ] && cat "$f" >> "$master" || true
        done
        sort -u "$master" -o "$master" 2>/dev/null || true
        print_success "Merged subdomain list: 00_all_subdomains.txt ($(wc -l < "$master") entries)"
    fi
}

# URL collection from archives
collect_urls() {
    print_info "Collecting archived URLs..."

    if [ "$HAVE_WAYBACKURLS" = true ]; then
        {
            printf '%s\n' "$TARGET"
            [ -s "${RESULTS_DIR}/00_all_subdomains.txt" ] && cat "${RESULTS_DIR}/00_all_subdomains.txt" || true
        } | sort -u | while IFS= read -r host; do
            [ -n "$host" ] && printf '%s\n' "$host" | waybackurls || true
        done | sort -u > "${RESULTS_DIR}/14_waybackurls.txt" 2>&1 || true
        write_no_results_note "${RESULTS_DIR}/14_waybackurls.txt" "No waybackurls results returned for ${TARGET}."
        print_success "Results saved to 14_waybackurls.txt"
    fi

    if [ "$HAVE_GAU" = true ]; then
        {
            printf '%s\n' "$TARGET"
            [ -s "${RESULTS_DIR}/00_all_subdomains.txt" ] && cat "${RESULTS_DIR}/00_all_subdomains.txt" || true
        } | sort -u | while IFS= read -r host; do
            [ -n "$host" ] && gau --threads "$THREADS" "$host" || true
        done | sort -u > "${RESULTS_DIR}/15_gau.txt" 2>&1 || true
        write_no_results_note "${RESULTS_DIR}/15_gau.txt" "No gau results returned for ${TARGET}."
        print_success "Results saved to 15_gau.txt"
    fi

    # Merge & deduplicate all URL sources
    local url_master="${RESULTS_DIR}/00_all_urls.txt"
    : > "$url_master"
    if [ "$HAVE_ANEW" = true ]; then
        for f in "${RESULTS_DIR}/14_waybackurls.txt" "${RESULTS_DIR}/15_gau.txt"; do
            [ -s "$f" ] && grep -E '^https?://' "$f" 2>/dev/null | anew "$url_master" > /dev/null 2>&1 || true
        done
        if [ -s "$url_master" ]; then
            print_success "Deduplicated URL list: 00_all_urls.txt ($(wc -l < "$url_master") entries)"
        else
            print_warning "00_all_urls.txt is empty. Archive tools returned no URLs for ${TARGET}."
        fi
    else
        for f in "${RESULTS_DIR}/14_waybackurls.txt" "${RESULTS_DIR}/15_gau.txt"; do
            [ -s "$f" ] && grep -E '^https?://' "$f" 2>/dev/null >> "$url_master" || true
        done
        sort -u "$url_master" -o "$url_master" 2>/dev/null || true
        [ -s "$url_master" ] && print_success "Merged URL list: 00_all_urls.txt ($(wc -l < "$url_master") entries)" || print_warning "00_all_urls.txt is empty. Archive tools returned no URLs for ${TARGET}."
    fi
}

# Port scanning
port_scan() {
    if [ "$QUICK_MODE" = true ]; then
        print_info "Quick mode enabled, skipping heavy port scans"
        return 0
    fi

    if [ "$HAVE_NMAP" = true ]; then
        print_info "Running Nmap service discovery..."
        nmap -Pn -sV -sC --top-ports 1000 "$TARGET" -oN "${RESULTS_DIR}/16_nmap.txt" > /dev/null 2>&1 || true
        print_success "Results saved to 16_nmap.txt"
    fi

    if [ "$HAVE_MASSCAN" = true ]; then
        print_info "Running Masscan top ports sweep..."
        masscan "$TARGET" --top-ports 1000 --rate "$RATE_LIMIT" > "${RESULTS_DIR}/17_masscan.txt" 2>&1 || true
        print_success "Results saved to 17_masscan.txt"
    fi
}

# Directory & endpoint fuzzing
dir_fuzz() {
    if [ "$QUICK_MODE" = true ]; then
        print_info "Quick mode enabled, skipping directory fuzzing"
        return 0
    fi

    # Resolve a wordlist — prefer SecLists, fall back to dirb common
    local wordlist=""
    local candidates=(
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        "/usr/share/seclists/Discovery/Web-Content/common.txt"
        "/usr/share/wordlists/dirb/common.txt"
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    )
    for wl in "${candidates[@]}"; do
        if [ -f "$wl" ]; then
            wordlist="$wl"
            break
        fi
    done

    if [ -z "$wordlist" ]; then
        print_warning "No wordlist found for directory fuzzing. Install seclists: apt install seclists"
        return 0
    fi

    print_debug "Using wordlist: $wordlist"

    if [ "$HAVE_FFUF" = true ]; then
        print_info "Running ffuf directory fuzzing (HTTP)..."
        ffuf -u "http://${TARGET}/FUZZ" \
             -w "$wordlist" \
             -mc 200,204,301,302,307,401,403,405 \
             -t "$THREADS" \
             -timeout "$TIMEOUT" \
             -of json \
             -o "${RESULTS_DIR}/20_ffuf_http.json" \
             -s 2>/dev/null || true
        # Also write a human-readable plain version
        ffuf -u "http://${TARGET}/FUZZ" \
             -w "$wordlist" \
             -mc 200,204,301,302,307,401,403,405 \
             -t "$THREADS" \
             -timeout "$TIMEOUT" \
             -s \
             > "${RESULTS_DIR}/20_ffuf_http.txt" 2>&1 || true
        print_success "Results saved to 20_ffuf_http.txt / 20_ffuf_http.json"

        print_info "Running ffuf directory fuzzing (HTTPS)..."
        ffuf -u "https://${TARGET}/FUZZ" \
             -w "$wordlist" \
             -mc 200,204,301,302,307,401,403,405 \
             -t "$THREADS" \
             -timeout "$TIMEOUT" \
             -of json \
             -o "${RESULTS_DIR}/21_ffuf_https.json" \
             -s 2>/dev/null || true
        ffuf -u "https://${TARGET}/FUZZ" \
             -w "$wordlist" \
             -mc 200,204,301,302,307,401,403,405 \
             -t "$THREADS" \
             -timeout "$TIMEOUT" \
             -s \
             > "${RESULTS_DIR}/21_ffuf_https.txt" 2>&1 || true
        print_success "Results saved to 21_ffuf_https.txt / 21_ffuf_https.json"
    fi

    if [ "$HAVE_GOBUSTER" = true ]; then
        print_info "Running gobuster directory brute-force (HTTPS)..."
        gobuster dir \
            -u "https://${TARGET}" \
            -w "$wordlist" \
            -t "$THREADS" \
            --timeout "${TIMEOUT}s" \
            -o "${RESULTS_DIR}/22_gobuster_dir.txt" \
            -q 2>/dev/null || true
        print_success "Results saved to 22_gobuster_dir.txt"

        print_info "Running gobuster vhost enumeration..."
        gobuster vhost \
            -u "https://${TARGET}" \
            -w "$wordlist" \
            -t "$THREADS" \
            --timeout "${TIMEOUT}s" \
            -o "${RESULTS_DIR}/23_gobuster_vhost.txt" \
            -q 2>/dev/null || true
        print_success "Results saved to 23_gobuster_vhost.txt"
    fi

    if [ "$HAVE_FEROXBUSTER" = true ]; then
        print_info "Running feroxbuster recursive content discovery (HTTPS)..."
        feroxbuster \
            --url "https://${TARGET}" \
            --wordlist "$wordlist" \
            --threads "$THREADS" \
            --timeout "$TIMEOUT" \
            --status-codes 200,204,301,302,307,401,403,405 \
            --auto-tune \
            --redirects \
            --extract-links \
            --output "${RESULTS_DIR}/26_feroxbuster_https.txt" \
            --quiet 2>/dev/null || true
        print_success "Results saved to 26_feroxbuster_https.txt"

        print_info "Running feroxbuster recursive content discovery (HTTP)..."
        feroxbuster \
            --url "http://${TARGET}" \
            --wordlist "$wordlist" \
            --threads "$THREADS" \
            --timeout "$TIMEOUT" \
            --status-codes 200,204,301,302,307,401,403,405 \
            --auto-tune \
            --redirects \
            --extract-links \
            --output "${RESULTS_DIR}/27_feroxbuster_http.txt" \
            --quiet 2>/dev/null || true
        print_success "Results saved to 27_feroxbuster_http.txt"

        # Recursive scan across all discovered subdomains (depth=2 to stay focused)
        if [ -s "${RESULTS_DIR}/00_all_subdomains.txt" ]; then
            print_info "Running feroxbuster across all discovered subdomains..."
            while IFS= read -r sub; do
                [ -z "$sub" ] && continue
                local safe_name
                safe_name=$(echo "$sub" | tr '.' '_')
                feroxbuster \
                    --url "https://${sub}" \
                    --wordlist "$wordlist" \
                    --threads "$THREADS" \
                    --timeout "$TIMEOUT" \
                    --status-codes 200,204,301,302,307,401,403,405 \
                    --auto-tune \
                    --redirects \
                    --depth 2 \
                    --output "${RESULTS_DIR}/ferox_${safe_name}.txt" \
                    --quiet 2>/dev/null || true
            done < "${RESULTS_DIR}/00_all_subdomains.txt"
            print_success "Feroxbuster subdomain scans saved to ferox_*.txt"
        fi
    fi
}

# Lightweight web vulnerability scan
vulnerability_scan() {
    if [ "$QUICK_MODE" = true ]; then
        print_info "Quick mode enabled, skipping heavy vulnerability scans"
        return 0
    fi

    if [ "$HAVE_NUCLEI" = true ]; then
        print_info "Running nuclei on target..."
        printf '%s\n' "https://${TARGET}" "http://${TARGET}" | \
            nuclei -silent \
                   -rate-limit "$RATE_LIMIT" \
                   -severity low,medium,high,critical \
                   -o "${RESULTS_DIR}/24_nuclei.txt" 2>&1 || true
        print_success "Results saved to 24_nuclei.txt"

        # Second pass: run on all discovered subdomains if available
        if [ -s "${RESULTS_DIR}/00_all_subdomains.txt" ]; then
            print_info "Running nuclei on all discovered subdomains..."
            cat "${RESULTS_DIR}/00_all_subdomains.txt" | \
                sed 's|^|https://|' | \
                nuclei -silent \
                       -rate-limit "$RATE_LIMIT" \
                       -severity low,medium,high,critical \
                       -o "${RESULTS_DIR}/24_nuclei_subdomains.txt" 2>&1 || true
            print_success "Results saved to 24_nuclei_subdomains.txt"
        fi
    fi

    if [ "$HAVE_NIKTO" = true ]; then
        print_info "Running nikto web scan..."
        nikto -h "https://${TARGET}" \
              -output "${RESULTS_DIR}/25_nikto.txt" \
              -Format txt 2>/dev/null || \
        nikto -h "https://${TARGET}" > "${RESULTS_DIR}/25_nikto.txt" 2>&1 || true
        print_success "Results saved to 25_nikto.txt"
    fi
}

# Create output directory
setup_output_dir() {
    mkdir -p "$RESULTS_DIR"
    print_success "Output directory created: $RESULTS_DIR"
    echo ""
}

# Display usage
usage() {
    cat << EOF
Usage: $0 [options] <target_host>

Description:
    Run an advanced bug bounty reconnaissance workflow against a target host.
  Results are saved to './recon_results/<target>_<timestamp>/' directory.

Arguments:
  target_host   : Hostname or IP address to scan

Options:
    -q, --quick           Skip heavier scans such as nmap, masscan, nuclei, nikto
    -v, --verbose         Enable debug output
    -t, --timeout SEC     Set request timeout (default: 10)
    -r, --rate-limit NUM  Set tool rate limit where supported (default: 1000)
    -h, --help            Show this help text

Examples:
    $0 tesla.com
    $0 -q -v example.com
    $0 --timeout 15 --rate-limit 500 example.com

Tools executed:
    - nslookup    : Baseline DNS lookup
    - dig         : Advanced DNS queries (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR, SRV, DNSKEY, DMARC, SPF, trace)
    - dnsrecon    : Deep DNS recon and zone analysis
    - whois       : Registration and ASN related information
    - curl/httpx  : Header checks, redirects, titles, tech detection
    - whatweb     : Technology fingerprinting
    - subfinder   : Passive subdomain enumeration
    - assetfinder : Additional passive subdomain discovery
    - amass       : Passive attack surface expansion
    - waybackurls/gau : Historical URL collection
    - nmap/masscan: Port and service discovery
    - ffuf         : Directory fuzzing (HTTP+HTTPS, JSON+plain) AND subdomain fuzzing
                     via DNS mode (FUZZ.target) and vhost mode (Host header)
    - gobuster     : Directory brute-force and vhost enumeration
    - feroxbuster  : Recursive content discovery on main target + all subdomains
                     (auto-tune, redirect follow, link extraction, depth=2 on subs)
    - nuclei/nikto : Vulnerability scanning (per-target and across all subdomains)
    - anew         : Deduplication — merges subdomain and URL lists into
                     00_all_subdomains.txt and 00_all_urls.txt

Note: Results are saved to timestamped directories for organization.

EOF
}

# Main execution flow
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -* )
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done

    if [[ -z "$TARGET" ]]; then
        usage
        exit 1
    fi

    RESULTS_DIR="${OUTPUT_DIR}/${TARGET}_${TIMESTAMP}"

    show_banner
    echo "Target: $TARGET"
    echo "Timestamp: $TIMESTAMP"
    echo "Quick mode: $QUICK_MODE"
    echo "Timeout: ${TIMEOUT}s"
    echo "Rate limit: $RATE_LIMIT"
    echo ""
    
    check_tools
    setup_output_dir
    
    print_header "Starting Reconnaissance"
    echo ""
    
    # Run tools in sequence
    dns_lookup_nslookup || true
    echo ""
    
    dns_lookup_dig || true
    echo ""

    dns_deep_recon || true
    echo ""
    
    whois_lookup || true
    echo ""
    
    curl_headers || true
    echo ""

    http_probe || true
    echo ""

    fingerprint_web || true
    echo ""
    
    reverse_dns_lookup || true
    echo ""
    
    subdomain_enum || true
    echo ""

    collect_urls || true
    echo ""

    port_scan || true
    echo ""

    dir_fuzz || true
    echo ""

    vulnerability_scan || true
    echo ""
    
    print_header "Reconnaissance Complete"
    print_success "All results saved to: $RESULTS_DIR"
    echo ""
    echo "Generated files:"
    ls -lh "$RESULTS_DIR"
}

# Run main function
main "$@"

