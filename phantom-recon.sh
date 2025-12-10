#!/bin/bash

# Enhanced Recon Automation Tool with Cool Features (Hardened)
# Performs comprehensive reconnaissance on a target domain
# Updated: Hardened URL sanitization + robust Arjun handling

set -euo pipefail
IFS=$'\n\t'

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
PINK='\033[1;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Phantom Recon - Advanced Reconnaissance Suite
show_banner() {
    clear
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐"
    echo -e "│                                                              │"
    echo -e "│${BOLD}${WHITE}           ⚡ P H A N T O M   R E C O N ⚡                    ${NC}${CYAN}│"
    echo -e "│${PURPLE}          Advanced Reconnaissance & Analysis Suite            ${NC}${CYAN}│"
    echo -e "│                                                              │"
    echo -e "│     ${WHITE}[ Target Acquisition ]${NC}${CYAN} ❯ ${ORANGE}[ Asset Discovery ]${NC}${CYAN} ❯ ${GREEN}[ Analysis ]${NC}${CYAN}│"
    echo -e "│                                                              │"
    echo -e "├──────────────────────────────────────────────────────────────┤"
    echo -e "│  ${WHITE}🔍 Subdomain Enumeration     🎯 Parameter Discovery${NC}${CYAN}         │"
    echo -e "│  ${WHITE}⚡ Live Host Detection       🔮 JavaScript Analysis${NC}${CYAN}         │"
    echo -e "│  ${WHITE}🌐 Asset Reconnaissance      🛡️ Vulnerability Scanning${NC}${CYAN}      │"
    echo -e "│                                                              │"
    echo -e "└──────────────────────────────────────────────────────────────┘${NC}"
    echo
}

progress_indicator() {
    local message=$1
    echo -e "\n${YELLOW}┌──────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} 🚀 $message"
    echo -e "${YELLOW}└──────────────────────────────────────┘${NC}"
    local spinstr='⣾⣽⣻⢿⡿⣟⣯⣷'
    local temp
    echo -n "  "
    for i in {1..15}; do
        temp=${spinstr#?}
        printf " ${CYAN}[%c]${NC} " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.08
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

section_header() {
    local title="$1"
    local title_length=${#title}
    local padding=$(( (50 - title_length) / 2 ))
    local pad_str=$(printf '%*s' "$padding" ' ')
    echo -e "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
    echo -e "┃${pad_str}${BOLD}${WHITE}$title${NC}${PURPLE}${pad_str}        ┃"
    echo -e "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

print_status() { echo -e "${BLUE}[♦] ${BOLD}INFO${NC}    ❯ $1"; }
print_success() { echo -e "${GREEN}[♦] ${BOLD}SUCCESS${NC} ❯ $1"; }
print_warning() { echo -e "${YELLOW}[♦] ${BOLD}WARNING${NC} ❯ $1"; }
print_error() { echo -e "${RED}[♦] ${BOLD}ERROR${NC}   ❯ $1"; }

# Check dependencies
check_dependencies() {
    section_header "DEPENDENCY CHECK"
    tools=("subfinder" "assetfinder" "gau" "waybackurls" "katana" "arjun")
    missing=()
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    if ! command -v "httpx" &>/dev/null && ! command -v "httprobe" &>/dev/null; then
        missing+=("httpx or httprobe")
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing dependencies: ${missing[*]}"
        print_status "Please install missing tools before proceeding"
        exit 1
    fi
    print_success "All required dependencies are available"
}

# Setup directories
setup_directories() {
    section_header "INITIALIZATION"
    TARGET=$1
    RECON_DIR="$HOME/recon/$TARGET"
    if [ -d "$RECON_DIR" ]; then
        print_warning "Directory $RECON_DIR already exists. Continuing with existing directory."
    else
        mkdir -p "$RECON_DIR"
        print_success "Created workspace: $RECON_DIR"
    fi
    cd "$RECON_DIR"
    print_status "Working directory set to: $(pwd)"
}

# Subdomain enumeration (kept minimal for brevity)
subdomain_enum() {
    section_header "SUBDOMAIN ENUMERATION"
    print_status "Running subfinder..."
    subfinder -d "$TARGET" -silent -o subfinder.txt || true
    print_status "Running assetfinder..."
    assetfinder --subs-only "$TARGET" > assetfinder.txt || true
    cat subfinder.txt assetfinder.txt | sort -u > all_subs.txt
    SUBDOMAIN_COUNT=$(wc -l < all_subs.txt || echo 0)
    print_success "Discovered $SUBDOMAIN_COUNT unique subdomains"
    echo -e "\n${CYAN}Top 5 subdomains:${NC}"
    head -n 5 all_subs.txt | nl -ba
}

# Live host discovery (kept minimal)
live_host_discovery() {
    section_header "LIVE HOST DISCOVERY"
    if command -v "httpx" &>/dev/null; then
        print_status "Probing for live hosts with httpx..."
        cat all_subs.txt | httpx -silent -status -title -tech-detect -o alive_subs.txt || cat all_subs.txt | httpx -silent -o alive_subs.txt || true
    elif command -v "httprobe" &>/dev/null; then
        print_status "Probing for live hosts with httprobe..."
        cat all_subs.txt | httprobe -c 50 > alive_subs.txt || true
    else
        print_error "Neither httpx nor httprobe is available"
        exit 1
    fi
    ALIVE_COUNT=$(wc -l < alive_subs.txt || echo 0)
    print_success "Found $ALIVE_COUNT live hosts"
    echo -e "\n${CYAN}Top 5 live hosts:${NC}"
    head -n 5 alive_subs.txt | awk '{print $1}' | nl -ba
}

# URL collection (kept minimal)
url_collection() {
    section_header "URL COLLECTION"
    print_status "Fetching URLs with GAU..."
    if [ -f alive_subs.txt ]; then
        awk '{print $1}' alive_subs.txt | gau --threads 50 --blacklist png,jpg,gif,svg > gau_urls.txt || true
        awk '{print $1}' alive_subs.txt | waybackurls > wayback.txt || true
        katana -list alive_subs.txt -d 5 -js-crawl -o katana_urls.txt || true
    else
        print_warning "alive_subs.txt not found; skipping some collectors."
    fi
    cat gau_urls.txt wayback.txt katana_urls.txt 2>/dev/null | sort -u > all_urls.txt || true
    URL_COUNT=$(wc -l < all_urls.txt || echo 0)
    print_success "Collected $URL_COUNT unique URLs"
    echo -e "\n${CYAN}URL Statistics:${NC}"
    echo "• GAU URLs: $(wc -l < gau_urls.txt 2>/dev/null || echo 0)"
    echo "• Wayback URLs: $(wc -l < wayback.txt 2>/dev/null || echo 0)"
    echo "• Katana URLs: $(wc -l < katana_urls.txt 2>/dev/null || echo 0)"
}

# JavaScript analysis (kept minimal)
js_endpoint_extraction() {
    section_header "JAVASCRIPT ANALYSIS"
    if [ -f all_urls.txt ]; then
        grep -Ei "\.js$" all_urls.txt | sort -u > jsfiles.txt || true
        JS_COUNT=$(wc -l < jsfiles.txt || echo 0)
        print_success "Found $JS_COUNT JavaScript files"
    else
        print_warning "all_urls.txt not found; skipping JS extraction."
    fi
}

# ---------------------------
# Hardened Parameter Discovery
# ---------------------------
sanitize_and_prepare_arjun_input() {
    section_header "PARAMETER DISCOVERY - SANITIZATION"

    print_status "Sanitizing URLs from all_urls.txt..."
    # Create working file names
    SANITIZED="sanitized_urls.txt"
    SANITIZED_FOR_ARJUN="urls_for_arjun.txt"
    ARJUN_GOOD="arjun_input_good.txt"
    ARJUN_BAD="arjun_input_bad.txt"
    : > "$SANITIZED"
    : > "$SANITIZED_FOR_ARJUN"
    : > "$ARJUN_GOOD"
    : > "$ARJUN_BAD"

    if [ ! -f all_urls.txt ]; then
        print_warning "all_urls.txt not found — nothing to sanitize."
        return 0
    fi

    # Extract well-formed URLs using a conservative regex, strip common trailing punctuation
    # Note: This intentionally avoids greedy matching into subsequent garbage.
    # Regex extracts things starting with http/https up to whitespace or a set of terminators.
    grep -Eo 'https?://[^[:space:]"'\''<>{}|\^`]+(?=[[:space:]]|$)' all_urls.txt \
        | sed -E 's/[\)\]\},;:]$//' \
        | sed -E 's/["'\''\r\n]//g' \
        | awk '{ if (length($0) < 2048) print $0 }' \
        | sort -u > "$SANITIZED"

    # Remove obviously malformed lines (no dot after host, or spaces)
    awk 'BEGIN{IGNORECASE=1} \
         { if ($0 ~ /^https?:\/\/[A-Za-z0-9\.-]+/) print $0 }' "$SANITIZED" > "${SANITIZED}.tmp" && mv "${SANITIZED}.tmp" "$SANITIZED"

    print_success "Sanitization complete: $(wc -l < "$SANITIZED" || echo 0) URLs"

    print_status "Filtering URLs that contain parameters (contain '=') for Arjun..."
    grep -E '=' "$SANITIZED" | sort -u > "$SANITIZED_FOR_ARJUN" || true
    print_success "Candidate parameterized URLs: $(wc -l < "$SANITIZED_FOR_ARJUN" || echo 0)"

    if [ ! -s "$SANITIZED_FOR_ARJUN" ]; then
        print_warning "No parameterized URLs found to pass to Arjun."
        return 0
    fi

    print_status "Preflighting parameterized URLs (curl HEAD check) to avoid broken/malformed entries..."
    # For each candidate URL, do a quick HEAD (or GET fallback) with timeout. Keep only reachable ones.
    while IFS= read -r url; do
        # skip lines that look suspiciously concatenated (multiple http occurrences)
        if [[ $(grep -o "https?://" <<< "$url" | wc -l) -gt 1 ]]; then
            echo "$url" >> "$ARJUN_BAD"
            continue
        fi

        # perform HEAD request; if fails, try a lightweight GET; if both fail, log as bad
        if curl -s -I -L --max-time 8 --retry 1 "$url" >/dev/null 2>&1; then
            echo "$url" >> "$ARJUN_GOOD"
        elif curl -s -L --max-time 10 --retry 1 "$url" >/dev/null 2>&1; then
            echo "$url" >> "$ARJUN_GOOD"
        else
            echo "$url" >> "$ARJUN_BAD"
        fi
    done < "$SANITIZED_FOR_ARJUN"

    GOOD_COUNT=$(wc -l < "$ARJUN_GOOD" || echo 0)
    BAD_COUNT=$(wc -l < "$ARJUN_BAD" || echo 0)
    print_success "Preflight done. Good: $GOOD_COUNT  Bad/skipped: $BAD_COUNT"

    if [ "$BAD_COUNT" -gt 0 ]; then
        print_warning "Bad URLs logged to: $ARJUN_BAD"
    fi

    # Move good input to the file Arjun will consume
    if [ "$GOOD_COUNT" -gt 0 ]; then
        mv "$ARJUN_GOOD" urls_for_arjun.txt
        print_success "Arjun input prepared: urls_for_arjun.txt ($(wc -l < urls_for_arjun.txt) lines)"
    else
        print_warning "No valid URLs to run Arjun against after preflight."
    fi
}

run_arjun_safely() {
    section_header "PARAMETER DISCOVERY - RUN ARJUN"

    if [ ! -f urls_for_arjun.txt ]; then
        print_warning "urls_for_arjun.txt missing — skipping Arjun run."
        return 0
    fi

    # Allow arjun to fail without crashing the whole script
    set +e

    ARJUN_OUTPUT="arjun_params.txt"
    : > "$ARJUN_OUTPUT"

    print_status "Running Arjun on sanitized input (this may take time)..."
    # Try bulk run first
    arjun -i urls_for_arjun.txt -t 50 -oT "$ARJUN_OUTPUT" 2> arjun_run.log
    ARJUN_EXIT=$?

    if [ $ARJUN_EXIT -eq 0 ]; then
        print_success "Arjun finished successfully. Results in $ARJUN_OUTPUT"
    else
        print_warning "Arjun returned non-zero exit ($ARJUN_EXIT). Inspecting arjun_run.log and attempting per-URL fallback..."
        # Try per-URL to isolate bad items
        : > "$ARJUN_OUTPUT"
        while IFS= read -r url; do
            # skip empty lines
            [ -z "$url" ] && continue
            echo -e "\n[+] Running Arjun on single URL: $url"
            # run arjun for single URL and append results (silently continue on errors)
            arjun -u "$url" -oT tmp_arjun_single.txt 2>> arjun_run.log || true
            if [ -s tmp_arjun_single.txt ]; then
                cat tmp_arjun_single.txt >> "$ARJUN_OUTPUT"
            fi
            rm -f tmp_arjun_single.txt
        done < urls_for_arjun.txt

        # dedupe results
        if [ -f "$ARJUN_OUTPUT" ]; then
            sort -u "$ARJUN_OUTPUT" -o "$ARJUN_OUTPUT"
            print_success "Per-URL Arjun fallback completed. Consolidated results: $ARJUN_OUTPUT"
        else
            print_warning "No Arjun output produced by per-URL fallback."
        fi
    fi

    # restore strict mode
    set -e
}

parameter_discovery() {
    section_header "PARAMETER DISCOVERY"
    print_status "Preparing URLs for parameter discovery..."
    sanitize_and_prepare_arjun_input
    print_status "Running Arjun for parameter discovery..."
    run_arjun_safely

    if [ -f arjun_params.txt ]; then
        PARAM_COUNT=$(wc -l < arjun_params.txt || echo 0)
        print_success "Discovered $PARAM_COUNT parameters (arjun_params.txt)"
        echo -e "\n${CYAN}Top 5 discovered parameters:${NC}"
        head -n 5 arjun_params.txt | nl -ba
    else
        print_warning "No arjun_params.txt produced."
    fi
}

# Cleanup and merge
cleanup_and_merge() {
    section_header "RESULTS AGGREGATION"
    print_status "Merging all endpoints..."
    cat linkfinder_endpoints.txt jsparser_endpoints.txt xn_endpoints.txt arjun_params.txt 2>/dev/null | sort -u > final_endpoints.txt || true
    print_status "Filtering endpoints with parameters..."
    grep -E '=' final_endpoints.txt > endpoints_with_params.txt 2>/dev/null || true
    ENDPOINT_COUNT=$(wc -l < final_endpoints.txt || echo 0)
    PARAM_ENDPOINT_COUNT=$(wc -l < endpoints_with_params.txt || echo 0)
    print_success "Merged $ENDPOINT_COUNT unique endpoints"
    print_success "Found $PARAM_ENDPOINT_COUNT endpoints with parameters"
}

# Generate report
generate_report() {
    section_header "REPORT GENERATION"
    REPORT_FILE="recon_summary_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                    RECONNAISSANCE SUMMARY                     ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        echo "║ Target: $TARGET"
        echo "║ Date: $(date)"
        echo "║ Duration: $DURATION seconds"
        echo "╠══════════════════════════════════════════════════════════════╣"
        echo "║ Subdomains Found: $(wc -l < all_subs.txt 2>/dev/null || echo 0)"
        echo "║ Live Hosts: $(wc -l < alive_subs.txt 2>/dev/null || echo 0)"
        echo "║ URLs Collected: $(wc -l < all_urls.txt 2>/dev/null || echo 0)"
        echo "║ JavaScript Files: $(wc -l < jsfiles.txt 2>/dev/null || echo 0)"
        echo "║ Endpoints Discovered: $(wc -l < final_endpoints.txt 2>/dev/null || echo 0)"
        echo "║ Endpoints with Parameters: $(wc -l < endpoints_with_params.txt 2>/dev/null || echo 0)"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "TOP SUBDOMAINS:"
        head -n 10 all_subs.txt | nl -ba
        echo ""
        echo "TOP LIVE HOSTS:"
        head -n 10 alive_subs.txt | awk '{print $1}' | nl -ba
        echo ""
        echo "TOP ENDPOINTS:"
        head -n 10 final_endpoints.txt | nl -ba
        echo ""
        echo "========================================"
        echo "Report generated by Reconnaissance Automator"
        echo "========================================"
    } > "$REPORT_FILE"
    print_success "Report saved to: $REPORT_FILE"
}

# Final summary with creator signature
show_summary() {
    section_header "MISSION COMPLETE"
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗"
    echo -e "║                   RECONNAISSANCE COMPLETED                   ║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║ Target: ${CYAN}$TARGET${NC}${GREEN}                                          ║"
    echo -e "║ Duration: ${CYAN}$DURATION seconds${NC}${GREEN}                                   ║"
    echo -e "║ Results: ${CYAN}$HOME/recon/$TARGET${NC}${GREEN}                                 ║"
    echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "\n${YELLOW}Key Findings:${NC}"
    echo "• Subdomains: $(wc -l < all_subs.txt 2>/dev/null || echo 0)"
    echo "• Live Hosts: $(wc -l < alive_subs.txt 2>/dev/null || echo 0)"
    echo "• URLs: $(wc -l < all_urls.txt 2>/dev/null || echo 0)"
    echo "• Endpoints: $(wc -l < final_endpoints.txt 2>/dev/null || echo 0)"
    echo "• Parameters: $(wc -l < endpoints_with_params.txt 2>/dev/null || echo 0)"
    echo -e "\n${BLUE}Next Steps:${NC}"
    echo "1. Review endpoints_with_params.txt for potential vulnerabilities"
    echo "2. Inspect sanitized_urls.txt and arjun_input_bad.txt for odd entries"
    echo "3. Analyze JavaScript files for sensitive information"
    echo "4. Test live hosts for common vulnerabilities"
    echo -e "\n${YELLOW}Thank you for using ${BOLD}Reconnaissance Automator${NC}${YELLOW}!${NC}"
}

# Main function
main() {
    if [ -z "${1-}" ]; then
        print_error "No target specified. Usage: $0 <target-domain>"
        exit 1
    fi
    TARGET=$1
    START_TIME=$(date +%s)
    show_banner
    check_dependencies
    setup_directories "$TARGET"
    progress_indicator "Subdomain Enumeration"
    subdomain_enum
    progress_indicator "Live Host Discovery"
    live_host_discovery
    progress_indicator "URL Collection"
    url_collection
    progress_indicator "JavaScript Analysis"
    js_endpoint_extraction
    progress_indicator "Parameter Discovery"
    parameter_discovery
    progress_indicator "Results Aggregation"
    cleanup_and_merge
    generate_report
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    show_summary
}

# Execute main function
main "$@"
