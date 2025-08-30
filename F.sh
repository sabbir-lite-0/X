#!/bin/bash

# Google Cloud Shell Security Scanner
# Author: Security Researcher
# Usage: chmod +x gcloud_scan.sh && ./gcloud_scan.sh

echo "=============================================="
echo "   Google Cloud Shell Security Scanner"
echo "=============================================="
echo "[*] Scan started at: $(date)"
echo ""

# Output file
OUTPUT_FILE="gcloud_security_scan_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -i "$OUTPUT_FILE")
exec 2>&1

echo "[+] Scanning basic system information..."
echo "----------------------------------------"
whoami
id
echo ""

echo "[+] Checking environment variables..."
echo "----------------------------------------"
env | grep -E '(GOOGLE|GCLOUD|TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)'
echo ""

echo "[+] Checking file system permissions..."
echo "----------------------------------------"
find /home /tmp /opt -type f -perm -o=w 2>/dev/null | head -20
echo ""

echo "[+] Checking processes..."
echo "----------------------------------------"
ps aux | head -20
echo ""

echo "[+] Checking network connections..."
echo "----------------------------------------"
netstat -tulpn
echo ""

echo "[+] Checking Google Cloud configuration..."
echo "----------------------------------------"
gcloud config list
gcloud auth list
echo ""

echo "[+] Checking service account access..."
echo "----------------------------------------"
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token || echo "Failed to access metadata"
echo ""

echo "[+] Checking installed tools..."
echo "----------------------------------------"
which nmap python python3 node npm java ruby perl php go 2>/dev/null
echo ""

echo "[+] Checking history files..."
echo "----------------------------------------"
ls -la ~/.*_history 2>/dev/null
echo ""

echo "[+] Checking sensitive files..."
echo "----------------------------------------"
ls -la ~/.config/gcloud/ 2>/dev/null
ls -la /etc/passwd /etc/shadow 2>/dev/null
echo ""

echo "[+] Downloading and running LinPEAS..."
echo "----------------------------------------"
if command -v wget &> /dev/null; then
    wget -q https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh -s | head -100
elif command -v curl &> /dev/null; then
    curl -s https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh -s | head -100
else
    echo "[-] wget and curl not available, skipping LinPEAS"
fi
echo ""

echo "[+] Scan completed at: $(date)"
echo "[*] Results saved to: $OUTPUT_FILE"
echo ""
echo "=============================================="
echo "   Important: Follow Google's VRP guidelines"
echo "   Do not test on unauthorized resources"
echo "=============================================="
