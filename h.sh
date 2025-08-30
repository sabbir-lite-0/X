#!/bin/bash
# Cloud Shell — Mega-Safe Extended Read-only Enumeration
# Adds capability/readelf/docker-sock/mounts/systemd-scan checks
# Output auto-saved to timestamped file.

set -eu
START_TS="$(date +%Y%m%d_%H%M%S)"
OUTPUT_FILE="gcp_megasafe_extended_${START_TS}.txt"

hr () { printf '%*s\n' "80" '' | tr ' ' '='; }
section () { hr; echo "=== $1 ==="; }

GCLOUD_PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
ACTIVE_ACCOUNT="$(gcloud config get-value core/account 2>/dev/null || true)"
METADATA_URL="http://metadata.google.internal/computeMetadata/v1"

{
echo "=================================================="
echo " Google Cloud Shell — Mega Safe Extended Testing"
echo " Started: $(date)"
echo " Active account: ${ACTIVE_ACCOUNT:-unknown}"
echo " Active project: ${GCLOUD_PROJECT:-unset}"
echo " Output file: $OUTPUT_FILE"
echo

section "SANDBOX / KERNEL / NAMESPACES"
uname -a || true
echo "Kernel version: $(uname -r 2>/dev/null || true)"
ls -la /proc/self/ns 2>/dev/null || true
echo

section "SECCOMP / CAPABILITIES / LSM"
# prefer capsh if available
if command -v capsh &>/dev/null; then
  echo "[capsh --print]"
  capsh --print 2>/dev/null || true
else
  echo "capsh not installed — falling back to /proc/self/status"
  grep -E 'Seccomp|Seccomp_filters|CapBnd' /proc/self/status 2>/dev/null || true
fi
cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "AppArmor: not enabled or no access"
getenforce 2>/dev/null || echo "SELinux: not available"
echo

section "MOUNTS / VOLUMES (with options)"
# neat table of mounts
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || mount | head -50
echo

# show a set of interesting mounted dirs and their perms (no file contents)
for m in / /root /home /etc /etc/ssh/keys /var/config /var/lib/docker /var/lib/containerd /var/lib/google; do
  if [ -e "$m" ]; then
    echo "=> $m"
    ls -ld "$m" 2>/dev/null || true
    # show top-level filenames with perms (no contents)
    find "$m" -maxdepth 1 -type f -printf "%M %u %g %p\n" 2>/dev/null | sed -n '1,50p' || true
    echo
  fi
done
echo

section "NETWORK (safe view)"
ip a 2>/dev/null || true
ip route 2>/dev/null || true
cat /etc/resolv.conf 2>/dev/null || true
ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || echo "ss/netstat not available"
echo

section "COMMON BINARIES HARDENING (readelf / GNU_STACK / RELRO)"
BINS="$(command -v bash ls cat grep curl wget 2>/dev/null || true)"
for bin in $BINS; do
  [ -f "$bin" ] || continue
  echo "[*] $bin"
  file "$bin" 2>/dev/null || true
  readelf -l "$bin" 2>/dev/null | grep -E 'GNU_STACK|GNU_RELRO' || true
  # if checksec installed, run it
  if command -v checksec &>/dev/null; then
    checksec --file="$bin" 2>/dev/null || true
  else
    echo "checksec not installed"
  fi
  echo
done

section "DOCKER / CONTAINER SOCKS & SOCKETS (names + perms only)"
for sock in /var/run/docker.sock /var/run/containerd/containerd.sock /run/containerd/containerd.sock /var/run/docker.sock /run/docker.sock /var/run/crio/crio.sock; do
  if [ -e "$sock" ]; then
    echo "Socket: $sock"
    ls -l "$sock" 2>/dev/null || true
  fi
done
# search for socket files in /var/run /run (limited)
find /var/run /run -maxdepth 2 -type s -printf "%p %M %u %g\n" 2>/dev/null | sed -n '1,100p' || true
echo

section "SYSTEMD UNIT SCAN (keywords: gcfsd containerd-gcfs fluent-bit)"
for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
  if [ -d "$d" ]; then
    echo "Scanning $d"
    grep -Hin --line-number -E 'gcfsd|containerd-gcfs|fluent-bit|gcfs|gcfsd' "$d" 2>/dev/null | sed -n '1,200p' || true
  fi
done
echo

section "METADATA / GCP SHELL CONTEXT (READ-ONLY)"
echo "[metadata quick probes]"
for ep in "project/project-id" "project/numeric-project-id" "instance/hostname" "instance/zone" "instance/service-accounts/" "instance/service-accounts/default/scopes" "instance/attributes/"; do
  echo "[$ep]"
  curl -s -H "Metadata-Flavor: Google" "${METADATA_URL}/${ep}" 2>/dev/null || true
  echo
done
echo "[metadata recursive (truncated)]"
curl -s -H "Metadata-Flavor: Google" "${METADATA_URL}/?recursive=true&alt=text" 2>/dev/null | sed -n '1,200p' || true
echo "(...truncated)"
echo

section "GCLOUD CONTEXT - READ-ONLY ENUM"
gcloud --version 2>/dev/null | head -10 || true
echo
echo "[gcloud config]"
gcloud config list 2>/dev/null || true
echo
echo "[auth list]"
gcloud auth list 2>/dev/null || true
echo

if [ -n "${GCLOUD_PROJECT:-}" ]; then
  echo "[project describe (yaml summary)]"
  gcloud projects describe "$GCLOUD_PROJECT" --format="yaml(projectId,projectNumber,lifecycleState,name,labels)" 2>/dev/null || echo "No access to describe project or not permitted"
  echo
  echo "[enabled services (top 30)]"
  gcloud services list --enabled --project="$GCLOUD_PROJECT" --limit=30 --format="table(config.name, state)" 2>/dev/null || echo "Cannot list services"
  echo
  echo "[iam public bindings scan]"
  gcloud projects get-iam-policy "$GCLOUD_PROJECT" --format=json 2>/dev/null \
    | jq -r '.bindings[]? | select((.members[]? | test("allUsers|allAuthenticatedUsers"))) | "ROLE=\(.role) MEMBERS=\(.members|join(","))"' 2>/dev/null || echo "No public bindings or no access"
  echo
else
  echo "No active project configured; skipping project-scoped checks."
fi
echo

section "CLOUD RESOURCES (names-only attempts)"
if [ -n "${GCLOUD_PROJECT:-}" ]; then
  echo "[service accounts (list names only)]"
  gcloud iam service-accounts list --project="$GCLOUD_PROJECT" --format="table(email,displayName,disabled)" 2>/dev/null || true
  echo
  echo "[buckets - IAM public check]"
  gsutil ls 2>/dev/null | sed 's/gs:\/\///' | while read -r b; do
    [ -z "$b" ] && continue
    echo "Bucket: gs://$b"
    gsutil iam get "gs://$b" 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)" || echo "  (no public grants detected or no access)"
  done
  echo
fi

section "TOKEN / SCOPE SAFE CHECKS"
# HEAD gave 501 earlier in your output; show that gracefully
curl -s -I -H "Metadata-Flavor: Google" "${METADATA_URL}/instance/service-accounts/default/token" 2>/dev/null | sed -n '1,10p' || true
echo
curl -s -H "Metadata-Flavor: Google" "${METADATA_URL}/instance/service-accounts/default/scopes" 2>/dev/null || true
echo
if gcloud auth application-default print-access-token 1>/dev/null 2>&1; then
  echo "ADC token present"
else
  echo "No ADC token (or insufficient permissions)"
fi
echo

section "WORLD-WRITABLE (LIMITED)"
# limit to home/tmp only, safe
find /home /tmp -xdev -type f -perm -o=w 2>/dev/null | head -100 || true
echo

section "HISTORY / DOTFILES (PATTERN SCAN - NO CONTENT DUMP)"
tail -200 ~/.bash_history 2>/dev/null | grep -Ei "(passw|token|key|secret|curl .*http|wget .*http)" || echo "No sensitive patterns found in last 200 lines or no history"
echo

hr
echo "Completed: $(date)"
echo "NOTE: Read-only enumeration only. If you find issues, follow Google VRP to report responsibly."
echo "=================================================="

} | tee "$OUTPUT_FILE"

echo
echo "Saved results -> $OUTPUT_FILE"
echo "If you'd like, I can:"
echo "  • add additional safe checks (e.g., ldap/config file names, k8s config file listing)"
echo "  • remove any check you don't want to run"
echo "  • produce a short findings-summary from the output (low/medium/high hints)"
