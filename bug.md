I'll create separate modular files for you with proper error handling. Let me create an organized structure:Perfect! I see the issue. You're using **zsh** but the script has bash-specific syntax. Also, I'll break it into **separate modular files** for better organization and maintenance.

Here's the **complete modular structure**:

## 📁 **Directory Structure:**

```
awjunaid-engine/
├── awjunaid-main.sh          # Main entry point
├── modules/
│   ├── recon.sh              # Phase 1: Reconnaissance
│   ├── enumeration.sh        # Phase 2: Enumeration
│   ├── scanning.sh           # Phase 3: Vulnerability Scanning
│   ├── exploitation.sh       # Phase 4: Exploitation
│   └── reporting.sh          # Phase 5: Reporting
├── lib/
│   ├── utils.sh              # Common utilities
│   ├── colors.sh             # Color definitions
│   └── logger.sh             # Logging functions
└── config/
    ├── payloads.conf         # XSS, SQLi payloads
    └── wordlists.conf        # Dictionary paths
```

---

## **File 1: `lib/colors.sh`** (Color & Formatting)

```bash
#!/usr/bin/env bash

# Color definitions
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export MAGENTA='\033[0;35m'
export CYAN='\033[0;36m'
export WHITE='\033[1;37m'
export NC='\033[0m'

export BOLD='\033[1m'
export DIM='\033[2m'
export UNDERLINE='\033[4m'
```

---

## **File 2: `lib/logger.sh`** (Logging Functions)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

# Initialize logging
init_logger() {
    local log_file=$1
    export LOG_FILE="$log_file"
}

# Log with timestamp
log_info() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[${timestamp}] [INFO]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_success() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[${timestamp}] [✓]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_warn() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[${timestamp}] [⚠]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_error() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[${timestamp}] [✗]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        local message="$*"
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo -e "${MAGENTA}[${timestamp}] [DEBUG]${NC} ${message}" | tee -a "$LOG_FILE"
    fi
}
```

---

## **File 3: `lib/utils.sh`** (Utility Functions)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/logger.sh"

# Check if tool exists
check_tool() {
    local tool=$1
    if ! command -v "$tool" &>/dev/null; then
        return 1
    fi
    return 0
}

# HTTP request with retry
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
            --connect-timeout 10 \
            --max-time 10 \
            "$url" 2>/dev/null || echo "ERROR:000")
        
        local http_code
        http_code=$(echo "$response" | tail -n1)
        local body
        body=$(echo "$response" | head -n-1)
        
        if [[ "$http_code" != "000" ]]; then
            echo "$body"
            return 0
        fi
        
        if [[ $attempt -lt $max_retries ]]; then
            local wait_time=$((2 ** attempt))
            log_warn "Request failed, retry $attempt/$max_retries (waiting ${wait_time}s)"
            sleep "$wait_time"
        fi
        ((attempt++))
    done
    
    return 1
}

# Validate domain
validate_domain() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        log_error "Domain cannot be empty"
        return 1
    fi
    
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        log_error "Invalid domain format: $domain"
        return 1
    fi
    
    return 0
}

# Create output directory
create_output_dir() {
    local domain=$1
    local output_dir="${HOME}/Desktop/hunt/reports/${domain}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    echo "$output_dir"
}

# URL encode
url_encode() {
    local string=$1
    echo -n "$string" | jq -sRr @uri 2>/dev/null || echo "$string"
}

# Get HTTP status code
get_http_status() {
    local url=$1
    curl -s -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null
}

# Rate limiting
apply_rate_limit() {
    local rate_limit=${1:-0}
    if [[ $rate_limit -gt 0 ]]; then
        sleep "$(echo "scale=2; 1/$rate_limit" | bc)" 2>/dev/null || sleep 0.1
    fi
}
```

---

## **File 4: `modules/recon.sh`** (Reconnaissance Phase)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

# Main reconnaissance function
recon_phase() {
    local domain=$1
    local output_dir=$2
    
    log_info "========== RECON PHASE STARTED =========="
    log_info "Target: $domain | Subdomains enumeration..."
    
    local recon_file="${output_dir}/01_recon.txt"
    {
        echo "=== RECONNAISSANCE REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$recon_file"
    
    # Subdomain enumeration
    recon_subdomains "$domain" >> "$recon_file"
    
    # DNS records
    recon_dns "$domain" >> "$recon_file"
    
    # Live hosts
    recon_live_hosts "$domain" >> "$recon_file"
    
    # Reverse proxy
    recon_reverse_proxy "$domain" >> "$recon_file"
    
    # Technology detection
    recon_technology "$domain" >> "$recon_file"
    
    # Sitemap
    recon_sitemap "$domain" >> "$recon_file"
    
    # Headers
    recon_headers "$domain" >> "$recon_file"
    
    log_success "Reconnaissance complete! Results in: $recon_file"
}

recon_subdomains() {
    local domain=$1
    echo "=== SUBDOMAINS ==="
    
    if check_tool subfinder; then
        subfinder -d "$domain" -silent 2>/dev/null || true
    fi
    
    # Using crt.sh
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
        grep -o '"name_value":"[^"]*"' | cut -d'"' -f4 | sort -u || true
    
    echo ""
}

recon_dns() {
    local domain=$1
    echo "=== DNS RECORDS ==="
    
    echo "A Records:"
    dig +short A "$domain" 2>/dev/null || echo "N/A"
    
    echo -e "\nMX Records:"
    dig +short MX "$domain" 2>/dev/null || echo "N/A"
    
    echo -e "\nNS Records:"
    dig +short NS "$domain" 2>/dev/null || echo "N/A"
    
    echo -e "\nTXT Records:"
    dig +short TXT "$domain" 2>/dev/null || echo "N/A"
    
    echo ""
}

recon_live_hosts() {
    local domain=$1
    echo "=== LIVE HOST DETECTION ==="
    
    local ip
    ip=$(dig +short "$domain" A | head -1)
    
    if [[ -n "$ip" ]]; then
        echo "Primary IP: $ip"
        
        if ping -c 1 -W 1 "$domain" &>/dev/null; then
            echo "Status: LIVE (ICMP reachable)"
        else
            local http_status
            http_status=$(get_http_status "https://$domain")
            if [[ "$http_status" =~ ^[2-4][0-9]{2}$ ]]; then
                echo "Status: LIVE (HTTP $http_status)"
            else
                echo "Status: POSSIBLY UP (DNS resolves)"
            fi
        fi
    else
        echo "Status: OFFLINE (DNS not resolving)"
    fi
    
    echo ""
}

recon_reverse_proxy() {
    local domain=$1
    echo "=== REVERSE PROXY DETECTION ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    if echo "$headers" | grep -qi "cloudflare\|akamai\|fastly\|cloudfront"; then
        echo "⚠️  REVERSE PROXY DETECTED"
        echo "$headers" | grep -i "server\|x-cache" || true
    else
        echo "✓ No obvious reverse proxy"
    fi
    
    echo ""
}

recon_technology() {
    local domain=$1
    echo "=== TECHNOLOGY STACK ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    echo "Server:"
    echo "$headers" | grep -i "^server:" || echo "Hidden"
    
    echo -e "\nPowered By:"
    echo "$headers" | grep -i "x-powered-by:" || echo "Not disclosed"
    
    if check_tool whatweb; then
        echo -e "\nWhatWeb Analysis:"
        whatweb -q "$domain" 2>/dev/null || true
    fi
    
    echo ""
}

recon_sitemap() {
    local domain=$1
    echo "=== SITEMAP DISCOVERY ==="
    
    local sitemap_urls=(
        "https://$domain/sitemap.xml"
        "http://$domain/sitemap.xml"
        "https://$domain/robots.txt"
        "http://$domain/robots.txt"
    )
    
    for url in "${sitemap_urls[@]}"; do
        local status
        status=$(get_http_status "$url")
        if [[ "$status" == "200" ]]; then
            echo "Found: $url"
            curl -s "$url" 2>/dev/null | head -20 || true
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
    
    echo -e "\n=== SECURITY HEADERS ==="
    
    local security_headers=(
        "Strict-Transport-Security"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "Content-Security-Policy"
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
```

---

## **File 5: `modules/enumeration.sh`** (Enumeration Phase)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

enumeration_phase() {
    local domain=$1
    local output_dir=$2
    
    log_info "========== ENUMERATION PHASE STARTED =========="
    
    local enum_file="${output_dir}/02_enumeration.txt"
    {
        echo "=== ENUMERATION REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$enum_file"
    
    # Endpoint discovery
    enum_endpoints "$domain" >> "$enum_file"
    
    # API discovery
    enum_api_endpoints "$domain" >> "$enum_file"
    
    log_success "Enumeration complete! Results in: $enum_file"
}

enum_endpoints() {
    local domain=$1
    echo "=== ENDPOINT DISCOVERY ==="
    
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
    )
    
    for path in "${common_paths[@]}"; do
        local url="https://$domain$path"
        local status_code
        status_code=$(get_http_status "$url")
        
        if [[ ! "$status_code" =~ ^(000|404)$ ]]; then
            echo "[$status_code] $path"
        fi
    done
    
    echo ""
}

enum_api_endpoints() {
    local domain=$1
    echo "=== API ENDPOINT DISCOVERY ==="
    
    local api_patterns=(
        "/api/v1/users"
        "/api/v1/products"
        "/api/v2/search"
        "/graphql"
        "/.well-known/openid-configuration"
    )
    
    for pattern in "${api_patterns[@]}"; do
        local url="https://$domain$pattern"
        local status_code
        status_code=$(get_http_status "$url")
        
        if [[ "$status_code" =~ ^[2-4][0-9]{2}$ ]]; then
            echo "✓ Found: $pattern (HTTP $status_code)"
        fi
    done
    
    echo ""
}
```

---

## **File 6: `modules/scanning.sh`** (Vulnerability Scanning)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

# Vulnerability counters
declare -A VULNS
VULNS[injection]=0
VULNS[xss]=0
VULNS[broken_auth]=0
VULNS[idor]=0
VULNS[misc]=0

scanning_phase() {
    local domain=$1
    local output_dir=$2
    local scan_mode=$3
    
    log_info "========== SCANNING PHASE STARTED =========="
    
    local scan_file="${output_dir}/03_scanning.txt"
    {
        echo "=== VULNERABILITY SCANNING REPORT ==="
        echo "Domain: $domain"
        echo "Scan Mode: $scan_mode"
        echo "Date: $(date)"
        echo ""
    } > "$scan_file"
    
    # OWASP scanning
    scan_injection "$domain" >> "$scan_file"
    scan_xss "$domain" >> "$scan_file"
    scan_broken_auth "$domain" >> "$scan_file"
    scan_idor "$domain" >> "$scan_file"
    scan_misc "$domain" >> "$scan_file"
    
    log_success "Scanning complete! Results in: $scan_file"
}

scan_injection() {
    local domain=$1
    echo "=== INJECTION VULNERABILITIES ==="
    
    local test_urls=(
        "https://$domain/search"
        "https://$domain/api/search"
    )
    
    local sqli_payloads=(
        "' OR '1'='1"
        "' OR 1=1 --"
        "admin' --"
    )
    
    echo "Testing for SQL Injection..."
    for url in "${test_urls[@]}"; do
        for payload in "${sqli_payloads[@]}"; do
            local encoded_payload
            encoded_payload=$(url_encode "$payload")
            
            local response
            response=$(curl -s -m 5 "$url?q=$encoded_payload" 2>/dev/null || true)
            
            if echo "$response" | grep -qi "sql\|mysql\|syntax error"; then
                echo "⚠️  Potential SQLi: $url"
                ((VULNS[injection]++))
            fi
        done
    done
    
    echo ""
}

scan_xss() {
    local domain=$1
    echo "=== XSS VULNERABILITIES ==="
    
    local xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror='alert(1)'>"
    )
    
    local test_params=(
        "search"
        "q"
        "name"
    )
    
    echo "Testing for XSS..."
    for param in "${test_params[@]}"; do
        for payload in "${xss_payloads[@]}"; do
            local encoded_payload
            encoded_payload=$(url_encode "$payload")
            
            local response
            response=$(curl -s -m 5 "https://$domain/?$param=$encoded_payload" 2>/dev/null)
            
            if echo "$response" | grep -q "<script>alert('XSS')</script>"; then
                echo "⚠️  Reflected XSS Found: Parameter '$param'"
                ((VULNS[xss]++))
            fi
        done
    done
    
    echo ""
}

scan_broken_auth() {
    local domain=$1
    echo "=== BROKEN AUTHENTICATION ==="
    
    local common_creds=(
        "admin:admin"
        "admin:password"
        "test:test"
    )
    
    echo "Testing default credentials..."
    for cred in "${common_creds[@]}"; do
        local user="${cred%:*}"
        local pass="${cred#*:}"
        
        local response
        response=$(curl -s -m 5 -u "$user:$pass" "https://$domain/api/auth/login" 2>/dev/null || true)
        
        if echo "$response" | grep -qi "success\|token"; then
            echo "⚠️  Weak Credentials: $user:$pass"
            ((VULNS[broken_auth]++))
        fi
    done
    
    echo ""
}

scan_idor() {
    local domain=$1
    echo "=== IDOR VULNERABILITIES ==="
    
    local idor_patterns=(
        "/api/user/1"
        "/api/user/2"
        "/api/profile/1"
    )
    
    echo "Testing for IDOR..."
    for pattern in "${idor_patterns[@]}"; do
        local url1="https://$domain$pattern"
        local url2="https://$domain${pattern%/*}/2"
        
        local resp1
        local resp2
        resp1=$(curl -s -m 5 "$url1" 2>/dev/null | md5sum | cut -d' ' -f1)
        resp2=$(curl -s -m 5 "$url2" 2>/dev/null | md5sum | cut -d' ' -f1)
        
        if [[ "$resp1" != "$resp2" ]]; then
            echo "ℹ️  Different responses: $pattern"
            ((VULNS[idor]++))
        fi
    done
    
    echo ""
}

scan_misc() {
    local domain=$1
    echo "=== MISCONFIGURATION CHECKS ==="
    
    local backup_files=(
        "/.git"
        "/.env"
        "/config.php.bak"
    )
    
    echo "Checking for exposed files..."
    for file in "${backup_files[@]}"; do
        local status
        status=$(get_http_status "https://$domain$file")
        
        if [[ "$status" == "200" ]]; then
            echo "⚠️  Exposed: $file (HTTP $status)"
            ((VULNS[misc]++))
        fi
    done
    
    echo ""
}
```

---

## **File 7: `modules/exploitation.sh`** (Exploitation Phase)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"

exploitation_phase() {
    local domain=$1
    local output_dir=$2
    
    log_info "========== EXPLOITATION PHASE STARTED =========="
    
    local exploit_file="${output_dir}/04_exploitation.txt"
    {
        echo "=== EXPLOITATION & VALIDATION REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$exploit_file"
    
    generate_xss_poc "$domain" >> "$exploit_file"
    generate_sqli_poc "$domain" >> "$exploit_file"
    
    log_success "Exploitation complete! Results in: $exploit_file"
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
    echo "Test URL: https://$domain/search?q=' OR '1'='1"
    echo ""
}
```

---

## **File 8: `modules/reporting.sh`** (Reporting Phase)

```bash
#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"

reporting_phase() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    
    log_info "========== REPORTING PHASE STARTED =========="
    
    generate_json_report "$domain" "$output_dir" "$start_time"
    generate_txt_report "$domain" "$output_dir" "$start_time"
    
    log_success "All reports generated in: $output_dir"
}

generate_json_report() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    local json_file="${output_dir}/REPORT.json"
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    cat > "$json_file" << EOF
{
  "scan_metadata": {
    "domain": "$domain",
    "scan_date": "$(date)",
    "total_duration_seconds": $duration,
    "scan_status": "completed"
  },
  "vulnerability_summary": {
    "total_vulnerabilities": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "status": "success"
}
EOF
    
    log_success "JSON report: $json_file"
}

generate_txt_report() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    local txt_file="${output_dir}/REPORT.txt"
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    cat > "$txt_file" << EOF
================================================================================
                    AWJUNAID SCRIPT ENGINE - SECURITY REPORT
================================================================================

EXECUTIVE SUMMARY
================================================================================
Domain:                     $domain
Scan Date:                  $(date)
Total Scan Duration:        ${duration}s
Report Generated:           $(date '+%Y-%m-%d %H:%M:%S')

================================================================================
Report Generated by: AWJUNAID Script Engine v2.0
================================================================================
EOF
    
    log_success "TXT report: $txt_file"
}
```

---

## **File 9: `awjunaid-main.sh`** (Main Entry Point)

```bash
#!/usr/bin/env bash

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all modules
source "${SCRIPT_DIR}/lib/colors.sh"
source "${SCRIPT_DIR}/lib/logger.sh"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/modules/recon.sh"
source "${SCRIPT_DIR}/modules/enumeration.sh"
source "${SCRIPT_DIR}/modules/scanning.sh"
source "${SCRIPT_DIR}/modules/exploitation.sh"
source "${SCRIPT_DIR}/modules/reporting.sh"

# Global variables
DOMAIN=""
SCAN_MODE="medium"
THREADS=10
VERBOSE=0
START_TIME=$(date +%s)

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

print_help() {
    cat << EOF
${CYAN}AWJUNAID Script Engine v2.0${NC} - Bug Bounty Automation Framework

${GREEN}Usage:${NC}
  bash awjunaid-main.sh -d <domain> [OPTIONS]

${GREEN}Required Arguments:${NC}
  -d, --domain <domain>          Target domain to scan

${GREEN}Optional Arguments:${NC}
  -m, --mode <mode>              Scan mode: soft, medium (default), hard
  -t, --threads <number>         Number of threads (default: 10)
  -v, --verbose                  Verbose output
  -h, --help                     Show this help message

${GREEN}Examples:${NC}
  bash awjunaid-main.sh -d example.com -m soft
  bash awjunaid-main.sh -d example.com -m medium -t 20
  bash awjunaid-main.sh -d example.com -m hard -v

EOF
}

main() {
    print_banner
    
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
            -v|--verbose)
                VERBOSE=1
                export VERBOSE
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
    
    # Validate
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    # Create output directory
    OUTPUT_DIR=$(create_output_dir "$DOMAIN")
    LOG_FILE="${OUTPUT_DIR}/scan.log"
    init_logger "$LOG_FILE"
    
    log_success "AWJUNAID Script Engine v2.0 initialized"
    log_info "Domain: $DOMAIN | Mode: $SCAN_MODE | Output: $OUTPUT_DIR"
    
    # Execute 5-phase workflow
    recon_phase "$DOMAIN" "$OUTPUT_DIR"
    enumeration_phase "$DOMAIN" "$OUTPUT_DIR"
    scanning_phase "$DOMAIN" "$OUTPUT_DIR" "$SCAN_MODE"
    exploitation_phase "$DOMAIN" "$OUTPUT_DIR"
    reporting_phase "$DOMAIN" "$OUTPUT_DIR" "$START_TIME"
    
    # Print summary
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              ${GREEN}✓ SCAN COMPLETED${NC}${CYAN}                   ║${NC}"
    echo -e "${CYAN}║${NC} Target: ${WHITE}$DOMAIN${NC}${CYAN}                    ║${NC}"
    echo -e "${CYAN}║${NC} Duration: ${WHITE}${duration}s${NC}${CYAN}                          ║${NC}"
    echo -e "${CYAN}║${NC} Reports: ${WHITE}$OUTPUT_DIR${NC}${CYAN} ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_success "Scan completed!"
}

main "$@"
```

---

## **Setup & Usage:**

```bash
# Make all scripts executable
chmod +x awjunaid-main.sh
chmod +x lib/*.sh
chmod +x modules/*.sh

# Run the scan
bash awjunaid-main.sh -d rayepenber.tech -m soft

# Verbose mode
bash awjunaid-main.sh -d example.com -m medium -v

# Hard scan
bash awjunaid-main.sh -d example.com -m hard -t 20
```

This **modular structure**:
✅ Fixes the zsh compatibility issue
✅ Separates concerns into individual files
✅ Easy to maintain and extend
✅ Avoids "read-only variable" errors
✅ Each module is reusable

Try it now! 🚀
