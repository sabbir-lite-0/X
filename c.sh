#!/bin/bash

echo "=================================================="
echo "   Google Cloud Shell Extended Security Testing"
echo "=================================================="
echo "[*] Testing started at: $(date)"
echo ""

OUTPUT_FILE="gcp_extended_testing_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== ADVANCED SAFE TESTS ==="

# 1. Syscalls / Seccomp Sandbox Checking
echo "[1] Checking Seccomp / Capabilities..."
grep Seccomp /proc/self/status 2>/dev/null || echo "No Seccomp info"
grep CapBnd /proc/self/status 2>/dev/null || echo "No CapBnd info"
echo ""

# 2. AppArmor / SELinux Profile Checking
echo "[2] Checking AppArmor / SELinux..."
cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "AppArmor not enabled"
getenforce 2>/dev/null || echo "SELinux not available"
echo ""

# 3. Metadata Deep Enumeration
echo "[3] Enumerating Metadata API..."
METADATA_URL="http://metadata.google.internal/computeMetadata/v1"
for endpoint in \
    "project/project-id" \
    "project/numeric-project-id" \
    "instance/hostname" \
    "instance/zone" \
    "instance/service-accounts/" \
    "instance/attributes/"; do
    echo "Endpoint: $endpoint"
    curl -s -H "Metadata-Flavor: Google" "$METADATA_URL/$endpoint"
    echo ""
done
echo ""

# 4. Network Isolation
echo "[4] Checking network isolation..."
ip a
ip route
cat /etc/resolv.conf
echo ""

# 5. Binary Hardening Check
echo "[5] Checking binary hardening..."
for bin in $(which bash ls cat grep curl wget 2>/dev/null); do
    if [ -f "$bin" ]; then
        echo "[*] Checking $bin"
        file $bin
        command -v checksec &>/dev/null && checksec --file=$bin || echo "checksec not installed"
    fi
done
echo ""

# 6. Cloud Misconfiguration Enumeration
echo "[6] Checking GCP configuration..."
gcloud config list 2>/dev/null
gcloud auth list 2>/dev/null
gcloud auth application-default print-access-token 2>/dev/null || echo "No ADC token"
echo ""

# 7. Resource Quotas & Limits
echo "[7] Checking resource limits..."
ulimit -a
cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo "No memory cgroup info"
cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || echo "No CPU cgroup info"
echo ""

# 8. Detect Shared Volumes / Mounts
echo "[8] Checking mounts..."
findmnt -t ext4,overlay,tmpfs
echo ""

echo "[*] Advanced Safe Testing completed at: $(date)"
echo "[!] Reminder: Review results carefully, report only valid findings to VRP"
} | tee "$OUTPUT_FILE"

echo ""
echo "=================================================="
echo "   Results saved to: $OUTPUT_FILE"
echo "=================================================="
