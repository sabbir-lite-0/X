#!/bin/bash

echo "=================================================="
echo "   Google Cloud Shell Misconfiguration Scanner"
echo "=================================================="
echo "[*] Scan started at: $(date)"
echo ""

OUTPUT_FILE="gcp_misconfig_scan_$(date +%Y%m%d_%H%M%S).txt"

{
echo "=== GCP PROJECT INFORMATION ==="
PROJECT_ID=$(gcloud config get-value project)
echo "Project ID: $PROJECT_ID"
echo ""

echo "=== IAM MISCONFIGURATION CHECKS ==="
echo "1. Checking for overly permissive IAM policies..."
gcloud projects get-iam-policy $PROJECT_ID --format=json | jq '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor" or .role == "roles/viewer")' 2>/dev/null
echo ""

echo "2. Checking for allUsers/allAuthenticatedUsers permissions..."
gcloud projects get-iam-policy $PROJECT_ID --format=json | grep -E "(allUsers|allAuthenticatedUsers)"
echo ""

echo "3. Checking service account permissions..."
gcloud iam service-accounts list --format="table(email, disabled)" 2>/dev/null
echo ""

echo "=== STORAGE MISCONFIGURATION CHECKS ==="
echo "4. Checking storage buckets for public access..."
for bucket in $(gsutil ls 2>/dev/null); do
    echo "Bucket: $bucket"
    gsutil iam get $bucket 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)"
    gsutil bucketpolicyonly get $bucket 2>/dev/null
    echo ""
done
echo ""

echo "=== COMPUTE MISCONFIGURATION CHECKS ==="
echo "5. Checking compute instances for public IP addresses..."
gcloud compute instances list --format="table(name,status,tags.list(),networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null
echo ""

echo "6. Checking firewall rules for overly permissive rules..."
gcloud compute firewall-rules list --format="table(name,network,direction,allowed.ports,sourceRanges)" 2>/dev/null | grep -E "(0.0.0.0/0|::/0)"
echo ""

echo "=== CLOUD SQL MISCONFIGURATION CHECKS ==="
echo "7. Checking Cloud SQL instances for public access..."
gcloud sql instances list --format="table(name,settings.ipConfiguration.requireSsl,settings.ipConfiguration.authorizedNetworks[0].value)" 2>/dev/null
echo ""

echo "=== KUBERNETES MISCONFIGURATION CHECKS ==="
echo "8. Checking GKE cluster configurations..."
gcloud container clusters list --format="table(name,masterAuthorizedNetworksConfig.enabled,privateClusterConfig.enablePrivateNodes)" 2>/dev/null
echo ""

echo "=== CLOUD FUNCTIONS MISCONFIGURATION CHECKS ==="
echo "9. Checking Cloud Functions for public access..."
gcloud functions list --format="table(name,ingressSettings)" 2>/dev/null
echo ""

echo "=== API MISCONFIGURATION CHECKS ==="
echo "10. Checking enabled APIs for known vulnerable services..."
gcloud services list --format="table(NAME)" 2>/dev/null | grep -E "(bigquery|datastore|firestore|pubsub|spanner)"
echo ""

echo "=== CLOUD SHELL SPECIFIC CHECKS ==="
echo "11. Checking Cloud Shell environment hardening..."
echo "Home directory permissions:"
ls -la ~/ | grep -E "\.(sh|py|js)$"
echo ""

echo "12. Checking environment for sensitive data leakage..."
env | grep -E "(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)" | grep -v "GOOGLE_APPLICATION_CREDENTIALS"
echo ""

echo "13. Checking shell history for sensitive commands..."
tail -20 ~/.bash_history | grep -E "(curl|wget|gcloud|gsutil|ssh|scp|passw)"
echo ""

echo "=== SECURITY BEST PRACTICE CHECKS ==="
echo "14. Checking for security command center setup..."
gcloud scc describe 2>/dev/null || echo "Security Command Center not enabled"
echo ""

echo "15. Checking for cloud audit logging configuration..."
gcloud logging sinks list --format="table(name,filter,destination)" 2>/dev/null
echo ""

echo "[*] Scan completed at: $(date)"
echo "[!] IMPORTANT: This is a non-destructive scan. Always follow Google's VRP guidelines."
} | tee "$OUTPUT_FILE"

echo "[+] Results saved to: $OUTPUT_FILE"
echo ""
echo "=================================================="
echo "   Next Steps:"
echo "   1. Review the results for misconfigurations"
echo "   2. Check for overly permissive IAM policies"
echo "   3. Ensure no public access to storage buckets"
echo "   4. Verify firewall rules are not overly permissive"
echo "   5. Report any findings through Google VRP"
echo "=================================================="
