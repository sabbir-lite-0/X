#!/bin/bash
# Cloud Shell — Advanced, Read-only, Safe Testing
# Focus: Sandbox/Hardening + GCP context (project/account) with default Cloud Shell access

set -u
START_TS="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="gcp_megasafe_testing_${START_TS}.txt"

# Small helpers
hr () { printf '%*s\n' "80" '' | tr ' ' '='; }
section () { hr; echo "=== $1 ==="; }

# Resolve current project/account safely
GCLOUD_PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
ACTIVE_ACCOUNT="$(gcloud config get-value core/account 2>/dev/null || true)"

{
echo "=================================================="
echo "     Google Cloud Shell Mega Safe Testing"
echo "=================================================="
echo "[*] Started at: $(date)"
echo "[*] Active account: ${ACTIVE_ACCOUNT:-unknown}"
echo "[*] Active project: ${GCLOUD_PROJECT:-unset}"
echo

########################################
section "SANDBOX / HARDENING / ISOLATION"
########################################

echo "[1] Kernel & namespaces"
uname -a
echo "Kernel version: $(uname -r)"
ls -la /proc/self/ns 2>/dev/null || true
echo

echo "[2] Seccomp / Caps / LSM"
grep -E 'Seccomp|Seccomp_filters|CapBnd' /proc/self/status 2>/dev/null || echo "No /proc/self/status"
# AppArmor / SELinux flags (read-only)
cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "AppArmor not enabled"
getenforce 2>/dev/null || echo "SELinux not available"
echo

echo "[3] Container / mount hints"
mount | head -50
echo
findmnt -t ext4,overlay,tmpfs 2>/dev/null || true
echo
for mnt in / /root /home /etc /etc/ssh/keys /var/config /var/lib/docker /var/lib/containerd; do
  [ -e "$mnt" ] && { echo "=> $mnt"; ls -ld "$mnt"; }
done
echo

echo "[4] Resources & cgroups"
ulimit -a
for f in \
 /sys/fs/cgroup/memory.max \
 /sys/fs/cgroup/memory/memory.limit_in_bytes \
 /sys/fs/cgroup/cpu.max \
 /sys/fs/cgroup/cpu/cpu.cfs_quota_us \
 /sys/fs/cgroup/cpuset.cpus; do
  [ -f "$f" ] && echo "$f: $(cat $f 2>/dev/null)"
done
echo

echo "[5] Network view (safe)"
ip a || true
ip route || true
cat /etc/resolv.conf || true
echo
ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || echo "No ss/netstat"
echo

echo "[6] Common binaries hardening snapshot"
BINS="$(command -v bash ls cat grep curl wget 2>/dev/null | tr '\n' ' ')"
for bin in $BINS; do
  [ -f "$bin" ] || continue
  echo "[*] $bin"
  file "$bin"
  readelf -l "$bin" 2>/dev/null | grep -E 'GNU_STACK|GNU_RELRO' || true
  command -v checksec &>/dev/null && checksec --file="$bin" || echo "checksec not installed"
done
echo

########################################
section "CLOUD SHELL / METADATA (READ-ONLY)"
########################################

METADATA_URL="http://metadata.google.internal/computeMetadata/v1"
echo "[7] Quick metadata probes (safe, header-guarded)"
for ep in \
 "project/project-id" \
 "project/numeric-project-id" \
 "instance/hostname" \
 "instance/zone" \
 "instance/service-accounts/" \
 "instance/service-accounts/default/scopes" \
 "instance/attributes/"; do
  echo "[$ep]"
  curl -s -H "Metadata-Flavor: Google" "$METADATA_URL/$ep" || true
  echo
done
echo

echo "[8] Recursive metadata (truncated for safety)"
curl -s -H "Metadata-Flavor: Google" "$METADATA_URL/?recursive=true&alt=text" | head -200 || true
echo "(…truncated…)"
echo

########################################
section "GCP CONTEXT (PROJECT / ACCOUNT) — READ-ONLY ENUM"
########################################

echo "[9] gcloud basics"
gcloud --version 2>/dev/null | head -5
echo
echo "[config]"
gcloud config list 2>/dev/null || true
echo "[auth]"
gcloud auth list 2>/dev/null || true
echo

echo "[10] Active project describe (if set)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud projects describe "$GCLOUD_PROJECT" --format="yaml(projectId,projectNumber,lifecycleState,name,labels)" 2>/dev/null || echo "No access to describe project"
else
  echo "No active project configured."
fi
echo

echo "[11] Billing (non-mutating)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud beta billing projects describe "$GCLOUD_PROJECT" 2>/dev/null || echo "Billing info not accessible"
fi
echo

echo "[12] Enabled services/APIs (top 50)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud services list --enabled --project="$GCLOUD_PROJECT" --format="table(config.name, state)" --limit=50 2>/dev/null || echo "Cannot list services"
fi
echo

echo "[13] IAM policy public bindings scan"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud projects get-iam-policy "$GCLOUD_PROJECT" --format=json 2>/dev/null \
   | jq -r '.bindings[]? | select((.members[]? | test("allUsers|allAuthenticatedUsers"))) | "ROLE=\(.role)  MEMBERS=\(.members|join(","))"' 2>/dev/null \
   || echo "No public bindings found or no access"
fi
echo

echo "[14] Service accounts (list only)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud iam service-accounts list --project="$GCLOUD_PROJECT" --format="table(email, displayName, disabled)" 2>/dev/null || echo "Cannot list service accounts"
fi
echo

echo "[15] Secret Manager (names only, if permitted)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud secrets list --project="$GCLOUD_PROJECT" --format="table(name, replication.policy)" 2>/dev/null || echo "No access to secrets list or none exist"
fi
echo

echo "[16] KMS keyrings/keys (catalog only)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  for loc in global us asia europe; do
    echo "Location: $loc"
    gcloud kms keyrings list --location="$loc" --project="$GCLOUD_PROJECT" --format="table(name)" 2>/dev/null || true
    gcloud kms keys list --location="$loc" --project="$GCLOUD_PROJECT" --format="table(name, purpose, rotationPeriod)" 2>/dev/null || true
  done
fi
echo

echo "[17] Storage buckets (IAM public flags only)"
gsutil ls 2>/dev/null | sed 's/gs:\/\///' | while read -r b; do
  [ -z "$b" ] && continue
  echo "Bucket: gs://$b"
  gsutil iam get "gs://$b" 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)" || echo "  (no public grants detected)"
done
echo

echo "[18] Compute (zones, instances — names only)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud compute zones list --project="$GCLOUD_PROJECT" --format="table(NAME, REGION, STATUS)" --limit=20 2>/dev/null || true
  gcloud compute instances list --project="$GCLOUD_PROJECT" --format="table(NAME, ZONE, STATUS)" --limit=50 2>/dev/null || echo "No instances or no access"
fi
echo

echo "[19] Artifact/Repos (names only)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud artifacts repositories list --project="$GCLOUD_PROJECT" --format="table(name, format, location)" 2>/dev/null || echo "No Artifact Registry access or none exist"
fi
echo

echo "[20] Cloud Logging quick read (very small, safe)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  gcloud logging logs list --project="$GCLOUD_PROJECT" --limit=10 2>/dev/null || echo "Cannot list logs"
  # show only log names, not entries
fi
echo

########################################
section "TOKEN / SCOPE (SAFE) — NO WRITE"
########################################

echo "[21] Metadata SA token HEAD check"
# Only proves accessibility; does not store token beyond transit
curl -s -I -H "Metadata-Flavor: Google" "$METADATA_URL/instance/service-accounts/default/token" | head -5 || true
echo

echo "[22] OAuth scopes from metadata"
curl -s -H "Metadata-Flavor: Google" "$METADATA_URL/instance/service-accounts/default/scopes" 2>/dev/null || true
echo

echo "[23] ADC presence check"
gcloud auth application-default print-access-token 1>/dev/null 2>&1 && echo "ADC token available" || echo "No ADC token"
echo

########################################
section "MISC SAFETY CHECKS"
########################################

echo "[24] World-writable files (home/tmp only, truncated)"
find /home /tmp -xdev -type f -perm -o=w 2>/dev/null | head -50
echo

echo "[25] Dotfiles / history quick peek (pattern only)"
tail -200 ~/.bash_history 2>/dev/null | grep -Ei "(passw|token|key|secret)" || echo "No sensitive patterns found in last 200 lines"
echo

########################################
hr
echo "[*] Completed at: $(date)"
echo "[!] NOTE: Read-only enumeration only. Report potential misconfigurations via VRP as appropriate."
echo "=================================================="

} | tee "$OUTPUT_FILE"

echo
echo "Saved results -> $OUTPUT_FILE"
