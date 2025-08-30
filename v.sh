#!/bin/bash

echo "=================================================="
echo "   Deep Google Cloud Shell Security Scanner"
echo "=================================================="
echo "[*] Scan started at: $(date)"
echo ""

# আউটপুট ফাইল
OUTPUT_FILE="deep_cloud_scan_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== SYSTEM INFORMATION ==="
whoami
id
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -a)"
echo ""

echo "=== CLOUD METADATA ==="
echo "Project ID: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id)"
echo "Instance ID: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/id)"
echo "Zone: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone)"
echo "Service Account: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email)"
echo ""

echo "=== CLOUD CONFIGURATION ==="
gcloud config list
gcloud auth list
echo ""

echo "=== IAM PERMISSIONS CHECK ==="
gcloud projects get-iam-policy $(gcloud config get-value project) --format=json | grep -E "(role|user|serviceAccount)"
echo ""

echo "=== SERVICE ACCOUNTS ==="
gcloud iam service-accounts list
echo ""

echo "=== COMPUTE INSTANCES ==="
gcloud compute instances list --format="table(name,status,machineType,zone)" | head -10
echo ""

echo "=== STORAGE BUCKETS ==="
gsutil ls 2>/dev/null | head -10
echo ""

echo "=== NETWORK CONFIGURATION ==="
gcloud compute networks list
gcloud compute firewall-rules list --format="table(name,network,direction,allowed.ports,sourceRanges)" | head -10
echo ""

echo "=== CLOUD SQL INSTANCES ==="
gcloud sql instances list --format="table(name,region,settings.tier,state)" 2>/dev/null | head -5
echo ""

echo "=== CLOUD FUNCTIONS ==="
gcloud functions list --format="table(name,runtime,status,trigger)" 2>/dev/null | head -5
echo ""

echo "=== CONTAINER REGISTRY ==="
gcloud container images list --format="table(name)" 2>/dev/null | head -5
echo ""

echo "=== KUBERNETES CLUSTERS ==="
gcloud container clusters list --format="table(name,location,master_version,status)" 2>/dev/null | head -5
echo ""

echo "=== ENVIRONMENT ANALYSIS ==="
echo "Current directory: $(pwd)"
echo "Home directory content:"
ls -la ~/ | head -10
echo ""

echo "=== PROCESS ANALYSIS ==="
ps aux --sort=-%cpu | head -15
echo ""

echo "=== NETWORK ANALYSIS ==="
netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null
echo ""

echo "=== FILE SYSTEM ANALYSIS ==="
echo "Mount points:"
mount | grep -E "(/home|/tmp|/dev)"
echo ""

echo "Writable directories:"
find /home /tmp -type d -perm -o=w 2>/dev/null | head -10
echo ""

echo "=== SECURITY CHECKS ==="
echo "SUID files:"
find / -type f -perm -4000 2>/dev/null | head -10
echo ""

echo "Capabilities:"
getcap -r / 2>/dev/null | head -10
echo ""

echo "=== CLOUD SHELL SPECIFIC ==="
echo "Cloud Shell specific environment variables:"
env | grep -E "(CLOUD|GOOGLE|DEVSELL|GCLOUD)" | grep -v "PASSWORD\|TOKEN\|KEY\|SECRET"
echo ""

echo "[*] Deep scan completed at: $(date)"
echo "[!] Remember to review results carefully and report any findings through Google VRP"
} | tee "$OUTPUT_FILE"

echo "[+] Results saved to: $OUTPUT_FILE"
echo ""
echo "=================================================="
echo "   Next steps:"
echo "   1. Review the output file: $OUTPUT_FILE"
echo "   2. Look for misconfigurations and excessive permissions"
echo "   3. Test for privilege escalation possibilities"
echo "   4. Report any vulnerabilities through Google VRP"
echo "=================================================="
