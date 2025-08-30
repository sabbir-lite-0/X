#!/bin/bash

echo "=================================================="
echo "   Google Cloud Shell Advanced Security Testing"
echo "=================================================="
echo "[*] Testing started at: $(date)"
echo ""

OUTPUT_FILE="gcp_advanced_testing_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== SANDBOX ESCAPE TESTS ==="
echo "1. Checking container isolation..."
echo "Current user: $(whoami)"
echo "Container ID: $(cat /proc/1/cgroup 2>/dev/null | grep docker | head -1)"
echo ""

echo "2. Attempting to access host system..."
mount | grep -E "(docker|overlay|hostPath)" 2>/dev/null
echo ""

echo "3. Checking for kernel vulnerabilities..."
uname -a
echo "Kernel version: $(uname -r)"
echo ""

echo "4. Testing namespace isolation..."
ls -la /proc/self/ns/ 2>/dev/null
echo ""

echo "=== PRIVILEGE ESCALATION TESTS ==="
echo "5. Checking SUID binaries..."
find / -perm -4000 -type f 2>/dev/null | grep -v "/snap/" | head -20
echo ""

echo "6. Checking sudo permissions..."
sudo -l 2>/dev/null || echo "No sudo access"
echo ""

echo "7. Checking capabilities..."
getcap -r / 2>/dev/null | head -10
echo ""

echo "8. Checking cron jobs..."
ls -la /etc/cron* 2>/dev/null
crontab -l 2>/dev/null || echo "No user cron jobs"
echo ""

echo "9. Checking environment variables for credentials..."
env | grep -E "(PASS|SECRET|KEY|TOKEN|CRED)" | grep -v "GOOGLE_APPLICATION_CREDENTIALS"
echo ""

echo "=== IDOR & API TESTING ==="
echo "10. Testing metadata API access..."
METADATA_URL="http://metadata.google.internal/computeMetadata/v1"
echo "Testing metadata access:"
curl -H "Metadata-Flavor: Google" "$METADATA_URL/instance/service-accounts/default/token" 2>/dev/null | head -2
echo ""

echo "11. Testing for service account token access..."
SA_TOKEN=$(curl -s -H "Metadata-Flavor: Google" "$METADATA_URL/instance/service-accounts/default/token")
if [ ! -z "$SA_TOKEN" ]; then
    echo "Service account token obtained successfully"
    ACCESS_TOKEN=$(echo "$SA_TOKEN" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    echo "Testing token permissions..."
    
    # Try to access various GCP APIs with the token
    echo "Testing Compute Engine API..."
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "https://compute.googleapis.com/compute/v1/projects/$(gcloud config get-value project)/zones" 2>/dev/null | head -3
    
    echo "Testing Storage API..."
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "https://storage.googleapis.com/storage/v1/b?project=$(gcloud config get-value project)" 2>/dev/null | head -3
else
    echo "Could not obtain service account token"
fi
echo ""

echo "12. Testing for IDOR in resource names..."
echo "Listing available projects:"
gcloud projects list --format="value(projectId)" --limit=5 2>/dev/null
echo ""

echo "13. Testing IAM permissions..."
gcloud projects get-iam-policy $(gcloud config get-value project) --format=json 2>/dev/null | \
  jq '.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers"))' 2>/dev/null || \
  echo "No public IAM bindings found"
echo ""

echo "14. Testing storage bucket permissions..."
for bucket in $(gsutil ls 2>/dev/null); do
    echo "Testing bucket: $bucket"
    gsutil iam get "$bucket" 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)" || true
done
echo ""

echo "=== NETWORK & SERVICE TESTS ==="
echo "15. Scanning local network..."
nmap -sS -T4 127.0.0.1 2>/dev/null | grep -E "(open|filtered)" || echo "Nmap not available"
echo ""

echo "16. Checking running services..."
netstat -tulpn 2>/dev/null | grep -v "127.0.0.1" | head -10
echo ""

echo "17. Testing for service misconfigurations..."
ps aux | grep -E "(redis|memcached|mongo|mysql|postgres)" | grep -v grep || echo "No common database services found"
echo ""

echo "=== FILE SYSTEM TESTS ==="
echo "18. Checking for sensitive files..."
find /home /tmp -name "*.key" -o -name "*.pem" -o -name "*.crt" -o -name "id_rsa*" -o -name "*.json" 2>/dev/null | head -10
echo ""

echo "19. Checking for world-writable files..."
find /home /tmp -type f -perm -o=w ! -type l 2>/dev/null | head -10
echo ""

echo "20. Checking shell history for sensitive data..."
tail -20 ~/.bash_history | grep -E "(passw|token|key|secret|curl.*http|wget.*http)" 2>/dev/null || echo "No sensitive commands in history"
echo ""

echo "[*] Testing completed at: $(date)"
echo "[!] IMPORTANT: This is for educational purposes only."
echo "[!] Always follow Google's VRP guidelines and only test on your own resources."
} | tee "$OUTPUT_FILE"

echo "[+] Results saved to: $OUTPUT_FILE"
echo ""
echo "=================================================="
echo "   Next Steps:"
echo "   1. Carefully review the results"
echo "   2. Look for misconfigurations and vulnerabilities"
echo "   3. If you find any vulnerabilities, report them through Google VRP"
echo "   4. Do not attempt to exploit vulnerabilities on unauthorized resources"
echo "=================================================="

# Additional advanced tests
echo ""
echo "=== ADVANCED TESTS ==="
echo "Running additional advanced tests..."

# Check for Docker escape possibilities
if command -v docker &> /dev/null; then
    echo "Checking Docker configuration..."
    docker ps -a 2>/dev/null | head -5
    docker images 2>/dev/null | head -5
fi

# Check for Kubernetes access
if command -v kubectl &> /dev/null; then
    echo "Checking Kubernetes access..."
    kubectl get pods 2>/dev/null | head -5
    kubectl get secrets 2>/dev/null | head -5
fi

# Check for cloud-specific misconfigurations
echo "Checking cloud-specific configurations..."
gcloud config list 2>/dev/null
gcloud info 2>/dev/null | head -10
