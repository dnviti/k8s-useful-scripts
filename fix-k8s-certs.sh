#!/bin/bash
###############################################################################
# fix-k8s-certs.sh
# Unified script to check and regenerate certificates on OpenShift (OCP)
# and RKE2 clusters.
#
# The platform type is detected automatically, or it can be forced with
# --platform=ocp|rke2.
#
# Usage: ./fix-k8s-certs.sh [OPTIONS]
#
# Common options:
#   --kubeconfig=PATH         Path to kubeconfig (multi-environment support)
#   --platform=ocp|rke2       Force platform (default: auto-detect)
#   --check-only              Check only, do not make changes
#
# OCP options:
#   --force-selfsigned        Immediately generate a self-signed cert without waiting
#   --fix-imagepull           Patch IfNotPresent for air-gapped clusters
#
# RKE2 options:
#   --fix-controlplane        Regenerate control plane certificates
#   --fix-ingress             Regenerate the ingress wildcard certificate
#   --fix-all                 Equivalent to --fix-controlplane --fix-ingress
#   --ingress-domain=FQDN     Wildcard domain for ingress
#   --rke2-data-dir=PATH      RKE2 data directory (default: /var/lib/rancher/rke2)
###############################################################################

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Colors and output functions
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*"; }
step()    { echo -e "\n${GREEN}━━━ STEP $1 ━━━${NC} $2"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────────${NC}"; }
banner()  { echo -e "${BOLD}${CYAN}$*${NC}"; }

# ─────────────────────────────────────────────────────────────────────────────
# Help (first, does not require dependencies)
# ─────────────────────────────────────────────────────────────────────────────
for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    cat <<'EOF'
Usage: fix-k8s-certs.sh [OPTIONS]

Common options:
  --kubeconfig=PATH         Path to kubeconfig (multi-environment support)
  --platform=ocp|rke2       Force platform (default: auto-detect)
  --check-only              Check certificates only, do not make changes
  --auto                    Non-interactive mode (no user input):
                            renew only if the cert expires within the threshold,
                            otherwise exit without changes. Ideal for cron.
  --auto-threshold=DAYS     Threshold in days for --auto (default: 7)

OpenShift (OCP) options:
  --force-selfsigned        Immediately generate a self-signed certificate
  --fix-imagepull           Patch imagePullPolicy=IfNotPresent (air-gapped)

RKE2 options:
  --fix-controlplane        Regenerate control plane certificates
  --fix-ingress             Regenerate the ingress wildcard certificate
  --fix-all                 Fix control plane + ingress
  --ingress-domain=FQDN     Wildcard domain (for example: apps.mycluster.it)
  --rke2-data-dir=PATH      RKE2 data directory (default: /var/lib/rancher/rke2)

Examples:
  # OpenShift — auto-detect
  ./fix-k8s-certs.sh --kubeconfig=/path/to/ocp-prod.kubeconfig

  # OpenShift — air-gapped with forced self-signed certificate
  ./fix-k8s-certs.sh --kubeconfig=/path/to/ocp.kubeconfig --force-selfsigned --fix-imagepull

  # RKE2 — check only
  ./fix-k8s-certs.sh --kubeconfig=/path/to/rke2-prod.yaml --check-only

  # RKE2 — full fix
  ./fix-k8s-certs.sh --kubeconfig=/path/to/rke2.yaml --fix-all --ingress-domain=apps.example.com

  # Force platform
  ./fix-k8s-certs.sh --platform=rke2 --kubeconfig=/path/to/kubeconfig --fix-controlplane

  # Cron job: renew OCP only if it expires within 7 days (default)
  ./fix-k8s-certs.sh --auto --kubeconfig=/path/to/ocp.kubeconfig

  # Cron job: renew OCP only if it expires within 30 days
  ./fix-k8s-certs.sh --auto --auto-threshold=30 --kubeconfig=/path/to/ocp.kubeconfig

  # Cron job: renew RKE2 control plane + ingress
  ./fix-k8s-certs.sh --auto --kubeconfig=/path/to/rke2.yaml --fix-all --ingress-domain=apps.example.com
EOF
    exit 0
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Dependency checks
# ─────────────────────────────────────────────────────────────────────────────
REQUIRED_TOOLS=(openssl jq base64 date sed grep tr mktemp)
OPTIONAL_TOOLS=(oc kubectl crictl systemctl awk wc)
MISSING_TOOLS=()
MISSING_OPTIONAL=()

for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    MISSING_TOOLS+=("$tool")
  fi
done

for tool in "${OPTIONAL_TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    MISSING_OPTIONAL+=("$tool")
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo -e "${RED}[ERROR]${NC} Missing required tools: ${MISSING_TOOLS[*]}"
  echo ""
  echo "  RHEL/CentOS/Fedora:  sudo dnf install -y jq openssl coreutils"
  echo "  Debian/Ubuntu:       sudo apt install -y jq openssl coreutils"
  echo "  SUSE/SLES:           sudo zypper install -y jq openssl coreutils"
  exit 1
fi

echo -e "${GREEN}[OK]${NC}    Required tools: ${REQUIRED_TOOLS[*]}"
if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
  echo -e "${YELLOW}[WARN]${NC}  Missing optional tools: ${MISSING_OPTIONAL[*]}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────
PLATFORM=""
KUBECONFIG_PATH=""
CHECK_ONLY=false
AUTO_MODE=false
AUTO_THRESHOLD_DAYS=7
# OCP-specific
FORCE_SELFSIGNED=false
FIX_IMAGEPULL=false
# RKE2-specific
FIX_CONTROLPLANE=false
FIX_INGRESS=false
INGRESS_DOMAIN=""
RKE2_DATA_DIR="/var/lib/rancher/rke2"
# Shared
CERT_VALIDITY_DAYS=730
WARN_DAYS=30

while [[ $# -gt 0 ]]; do
  case $1 in
    # Common
    --platform=*)           PLATFORM="${1#*=}"; shift ;;
    --platform)             PLATFORM="${2:-}"; shift 2 ;;
    --kubeconfig=*)         KUBECONFIG_PATH="${1#*=}"; shift ;;
    --kubeconfig)           KUBECONFIG_PATH="${2:-}"; shift 2 ;;
    --check-only)           CHECK_ONLY=true; shift ;;
    --auto)                 AUTO_MODE=true; shift ;;
    --auto-threshold=*)     AUTO_THRESHOLD_DAYS="${1#*=}"; shift ;;
    --auto-threshold)       AUTO_THRESHOLD_DAYS="${2:-}"; shift 2 ;;
    # OCP
    --force-selfsigned)     FORCE_SELFSIGNED=true; shift ;;
    --fix-imagepull)        FIX_IMAGEPULL=true; shift ;;
    # RKE2
    --fix-controlplane)     FIX_CONTROLPLANE=true; shift ;;
    --fix-ingress)          FIX_INGRESS=true; shift ;;
    --fix-all)              FIX_CONTROLPLANE=true; FIX_INGRESS=true; shift ;;
    --ingress-domain=*)     INGRESS_DOMAIN="${1#*=}"; shift ;;
    --ingress-domain)       INGRESS_DOMAIN="${2:-}"; shift 2 ;;
    --rke2-data-dir=*)      RKE2_DATA_DIR="${1#*=}"; shift ;;
    --rke2-data-dir)        RKE2_DATA_DIR="${2:-}"; shift 2 ;;
    -h|--help)              exit 0 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

# --auto-threshold validation
if [[ "$AUTO_MODE" == true ]]; then
  if ! [[ "$AUTO_THRESHOLD_DAYS" =~ ^[0-9]+$ ]] || [[ "$AUTO_THRESHOLD_DAYS" -lt 1 ]]; then
    err "--auto-threshold must be a positive integer (received: '$AUTO_THRESHOLD_DAYS')"
    exit 1
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Kubeconfig
# ─────────────────────────────────────────────────────────────────────────────
if [[ -n "$KUBECONFIG_PATH" ]]; then
  if [[ ! -f "$KUBECONFIG_PATH" ]]; then
    err "Kubeconfig not found: $KUBECONFIG_PATH"
    exit 1
  fi
  export KUBECONFIG="$KUBECONFIG_PATH"
  ok "Kubeconfig: $KUBECONFIG_PATH"
elif [[ -n "${KUBECONFIG:-}" ]]; then
  info "Kubeconfig from environment: $KUBECONFIG"
else
  # Auto-detect for RKE2
  for KC in /etc/rancher/rke2/rke2.yaml "$HOME/.kube/config"; do
    if [[ -f "$KC" ]]; then
      export KUBECONFIG="$KC"
      info "Auto-detected kubeconfig: $KC"
      break
    fi
  done
  if [[ -z "${KUBECONFIG:-}" ]]; then
    info "Kubeconfig: default (~/.kube/config)"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Detect available CLI (oc or kubectl)
# ─────────────────────────────────────────────────────────────────────────────
KUBECTL=""
if command -v oc &>/dev/null; then
  KUBECTL="oc"
elif command -v kubectl &>/dev/null; then
  KUBECTL="kubectl"
elif [[ -x "$RKE2_DATA_DIR/bin/kubectl" ]]; then
  KUBECTL="$RKE2_DATA_DIR/bin/kubectl"
elif [[ -x /var/lib/rancher/rke2/bin/kubectl ]]; then
  KUBECTL="/var/lib/rancher/rke2/bin/kubectl"
fi

if [[ -z "$KUBECTL" ]]; then
  err "No Kubernetes client found (oc or kubectl). Install one."
  exit 1
fi
ok "Kubernetes CLI: $KUBECTL"

# Check connection
CLUSTER_ACCESS=false
if $KUBECTL cluster-info &>/dev/null 2>&1; then
  CLUSTER_ACCESS=true
  ok "Cluster connection: active"
else
  # For OCP, try oc whoami
  if [[ "$KUBECTL" == "oc" ]] && oc whoami &>/dev/null 2>&1; then
    CLUSTER_ACCESS=true
    ok "Cluster connection: active (oc)"
  else
    err "Unable to connect to the cluster. Check kubeconfig and connectivity."
    exit 1
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Auto-detect platform
# ─────────────────────────────────────────────────────────────────────────────
if [[ -z "$PLATFORM" ]]; then
  info "Detecting platform..."

  # Method 1: OCP-specific resources
  if $KUBECTL get clusteroperators &>/dev/null 2>&1; then
    PLATFORM="ocp"
  # Method 2: check nodes with RKE2 labels
  elif $KUBECTL get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' 2>/dev/null | grep -qi "containerd"; then
    # Check whether it is RKE2 by looking at pods
    if $KUBECTL get pods -n kube-system -l app.kubernetes.io/name=rke2 &>/dev/null 2>&1 || \
       [[ -d "$RKE2_DATA_DIR/server/tls" ]] || \
       systemctl list-units --type=service 2>/dev/null | grep -q rke2; then
      PLATFORM="rke2"
    fi
  fi

  # Method 3: local filesystem
  if [[ -z "$PLATFORM" ]]; then
    if [[ -d "$RKE2_DATA_DIR/server/tls" ]]; then
      PLATFORM="rke2"
    fi
  fi

  if [[ -z "$PLATFORM" ]]; then
    err "Unable to detect platform. Specify --platform=ocp or --platform=rke2"
    exit 1
  fi
fi

# Validation
case "$PLATFORM" in
  ocp|openshift)  PLATFORM="ocp" ;;
  rke2|rancher)   PLATFORM="rke2" ;;
  *)
    err "Unsupported platform: $PLATFORM (use: ocp, rke2)"
    exit 1
    ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Common functions
# ─────────────────────────────────────────────────────────────────────────────
check_cert_file() {
  local CERT_PATH="$1"
  local CERT_NAME="$2"

  if [[ ! -f "$CERT_PATH" ]]; then
    warn "$CERT_NAME: file not found ($CERT_PATH)"
    return 1
  fi

  local NOT_AFTER SUBJECT EXPIRY_EPOCH NOW_EPOCH DAYS_LEFT
  NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
  SUBJECT=$(openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")

  if [[ -z "$NOT_AFTER" ]]; then
    warn "$CERT_NAME: unable to read certificate"
    return 1
  fi

  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if (( DAYS_LEFT < 0 )); then
    err "$CERT_NAME: EXPIRED $(( DAYS_LEFT * -1 )) days ago ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 2
  elif (( DAYS_LEFT < WARN_DAYS )); then
    warn "$CERT_NAME: expires in $DAYS_LEFT days ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 3
  else
    ok "$CERT_NAME: valid, expires in $DAYS_LEFT days ($NOT_AFTER)"
    return 0
  fi
}

check_cert_secret() {
  local NAMESPACE="$1"
  local SECRET_NAME="$2"
  local CERT_NAME="$3"
  local JSONPATH="${4:-.data.tls\.crt}"

  local CERT_DATA
  CERT_DATA=$($KUBECTL get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath="{$JSONPATH}" 2>/dev/null || echo "")

  if [[ -z "$CERT_DATA" ]]; then
    warn "$CERT_NAME: secret $SECRET_NAME not found in $NAMESPACE"
    return 1
  fi

  local NOT_AFTER EXPIRY_EPOCH NOW_EPOCH DAYS_LEFT SUBJECT
  NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
  SUBJECT=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")

  if [[ -z "$NOT_AFTER" ]]; then
    warn "$CERT_NAME: unable to decode certificate"
    return 1
  fi

  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if (( DAYS_LEFT < 0 )); then
    err "$CERT_NAME: EXPIRED $(( DAYS_LEFT * -1 )) days ago ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 2
  elif (( DAYS_LEFT < WARN_DAYS )); then
    warn "$CERT_NAME: expires in $DAYS_LEFT days ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 3
  else
    ok "$CERT_NAME: valid, expires in $DAYS_LEFT days ($NOT_AFTER)"
    return 0
  fi
}

generate_selfsigned_cert() {
  local DOMAIN="$1"
  local OUTDIR="$2"
  local DAYS="${3:-$CERT_VALIDITY_DAYS}"

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$OUTDIR/wildcard.key" \
    -x509 -days "$DAYS" \
    -out "$OUTDIR/wildcard.crt" \
    -subj "/CN=*.$DOMAIN" \
    -addext "subjectAltName=DNS:*.$DOMAIN,DNS:$DOMAIN" 2>/dev/null

  ok "Generated self-signed certificate (*.$DOMAIN, validity ${DAYS} days)"
  openssl x509 -in "$OUTDIR/wildcard.crt" -noout -dates
}

# ═══════════════════════════════════════════════════════════════════════════════
#  START
# ═══════════════════════════════════════════════════════════════════════════════
divider
banner "fix-k8s-certs.sh — Platform: ${PLATFORM^^} — $(date)"

if [[ "$AUTO_MODE" == true ]]; then
  info "Mode: AUTO (non-interactive, renewal threshold: ${AUTO_THRESHOLD_DAYS} days)"
fi

if [[ "$PLATFORM" == "ocp" ]]; then
  CLUSTER_USER=$($KUBECTL whoami 2>/dev/null || echo "N/A")
  CLUSTER_API=$($KUBECTL whoami --show-server 2>/dev/null || echo "N/A")
  info "User:    $CLUSTER_USER"
  info "Cluster: $CLUSTER_API"
else
  info "Cluster: $($KUBECTL cluster-info 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g' || echo 'N/A')"
fi
divider

# ═══════════════════════════════════════════════════════════════════════════════
#  OCP FLOW
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "ocp" ]]; then

  # ── STEP 1: Detect domain ──
  step 1 "Detecting wildcard apps domain"

  APPS_DOMAIN=$($KUBECTL get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}' 2>/dev/null || true)
  if [[ -z "$APPS_DOMAIN" ]]; then
    APPS_DOMAIN=$($KUBECTL get route console -n openshift-console -o jsonpath='{.spec.host}' 2>/dev/null | sed 's/^console-openshift-console\.//')
  fi
  if [[ -z "$APPS_DOMAIN" ]]; then
    err "Unable to determine the cluster apps domain."
    exit 1
  fi
  ok "Domain: $APPS_DOMAIN"
  WILDCARD_CN="*.$APPS_DOMAIN"

  # ── STEP 2: Check certificate ──
  step 2 "Checking current router certificate"

  CERT_DATA=$($KUBECTL get secret router-certs-default -n openshift-ingress \
    -o jsonpath='{.data.tls\.crt}' 2>/dev/null || true)

  if [[ -n "$CERT_DATA" ]]; then
    CERT_DATES=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -dates -subject 2>/dev/null || true)
    if [[ -n "$CERT_DATES" ]]; then
      echo "$CERT_DATES"
      NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
      NOW_EPOCH=$(date +%s)

      if (( EXPIRY_EPOCH > NOW_EPOCH )); then
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        ok "The certificate is still valid (expires in $DAYS_LEFT days: $NOT_AFTER)"

        if [[ "$CHECK_ONLY" == true ]]; then
          info "Check-only mode — no changes."
          exit 0
        fi

        if [[ "$AUTO_MODE" == true ]]; then
          if (( DAYS_LEFT <= AUTO_THRESHOLD_DAYS )); then
            warn "Auto mode: certificate expires in $DAYS_LEFT days (threshold: ${AUTO_THRESHOLD_DAYS} days) — proceeding with renewal"
          else
            ok "Auto mode: certificate expires in $DAYS_LEFT days (threshold: ${AUTO_THRESHOLD_DAYS} days) — no action needed"
            exit 0
          fi
        else
          echo ""
          read -rp "Do you want to continue with regeneration anyway? (y/N) " REPLY
          if [[ ! "$REPLY" =~ ^[sSyY]$ ]]; then
            info "Operation canceled."
            exit 0
          fi
        fi
      else
        warn "Certificate EXPIRED on $NOT_AFTER"
        if [[ "$AUTO_MODE" == true ]]; then
          info "Auto mode: certificate expired — proceeding with renewal"
        fi
      fi
    else
      warn "Unable to decode current certificate"
    fi
  else
    warn "Secret router-certs-default not found in openshift-ingress"
  fi

  # ── STEP 3: Operator status ──
  step 3 "Current status of impacted operators"

  for OP in authentication console ingress; do
    STATUS=$($KUBECTL get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null || echo "Unknown")
    DEGRADED=$($KUBECTL get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].status}' 2>/dev/null || echo "Unknown")
    if [[ "$DEGRADED" == "True" ]]; then
      warn "$OP: Available=$STATUS, Degraded=$DEGRADED"
    else
      ok "$OP: Available=$STATUS, Degraded=$DEGRADED"
    fi
  done

  if [[ "$CHECK_ONLY" == true ]]; then
    divider
    info "Check-only mode — no changes applied."
    exit 0
  fi

  # ── STEP 4: Delete router secret ──
  step 4 "Deleting secret router-certs-default"

  if $KUBECTL get secret router-certs-default -n openshift-ingress &>/dev/null; then
    $KUBECTL delete secret router-certs-default -n openshift-ingress
    ok "Secret deleted from openshift-ingress"
  else
    info "Secret already absent in openshift-ingress"
  fi

  # ── STEP 5: Restart ingress-operator ──
  step 5 "Restarting ingress-operator"

  $KUBECTL delete pods --all -n openshift-ingress-operator 2>/dev/null || true
  info "Pods deleted, waiting for restart..."
  sleep 5

  for i in $(seq 1 30); do
    PHASE=$($KUBECTL get pods -n openshift-ingress-operator -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "Pending")
    if [[ "$PHASE" == "Running" ]]; then
      ok "Ingress-operator Running"
      break
    fi
    echo -n "."
    sleep 2
  done
  echo ""

  # ── STEP 6: Wait for regeneration or force self-signed ──
  step 6 "Waiting for certificate regeneration"

  CERT_REGENERATED=false

  if [[ "$FORCE_SELFSIGNED" == false ]]; then
    info "Waiting for the ingress-operator to regenerate the secret (max 60s)..."
    for i in $(seq 1 12); do
      if $KUBECTL get secret router-certs-default -n openshift-ingress &>/dev/null; then
        NEW_DATES=$($KUBECTL get secret router-certs-default -n openshift-ingress \
          -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates 2>/dev/null || true)
        if [[ -n "$NEW_DATES" ]]; then
          ok "Secret automatically regenerated by the operator"
          echo "$NEW_DATES"
          CERT_REGENERATED=true
          break
        fi
      fi
      echo -n "."
      sleep 5
    done
    echo ""
  fi

  if [[ "$CERT_REGENERATED" == false ]]; then
    warn "Automatic regeneration did not happen — creating self-signed certificate"
    TMPDIR=$(mktemp -d)
    generate_selfsigned_cert "$APPS_DOMAIN" "$TMPDIR"

    $KUBECTL create secret tls router-certs-default \
      --cert="$TMPDIR/wildcard.crt" \
      --key="$TMPDIR/wildcard.key" \
      -n openshift-ingress
    ok "Secret router-certs-default created"
    rm -rf "$TMPDIR"
  fi

  # ── STEP 7: Restart router pods ──
  step 7 "Restarting router pods"

  $KUBECTL rollout restart deployment/router-default -n openshift-ingress 2>/dev/null || \
    $KUBECTL delete pods --all -n openshift-ingress 2>/dev/null || true
  info "Waiting for routers to become ready..."
  $KUBECTL rollout status deployment/router-default -n openshift-ingress --timeout=120s 2>/dev/null || \
    warn "Router rollout timed out — it may take more time"
  ok "Routers restarted"

  # ── STEP 8: Propagate to config-managed ──
  step 8 "Propagating certificate to openshift-config-managed"

  $KUBECTL delete secret router-certs-default -n openshift-config-managed 2>/dev/null || true
  $KUBECTL get secret router-certs-default -n openshift-ingress -o json | \
    jq '.metadata.namespace = "openshift-config-managed" |
        del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp, .metadata.managedFields)' | \
    $KUBECTL apply -f -
  ok "Secret copied to openshift-config-managed"

  # ── STEP 9: Clean authentication cache ──
  step 9 "Cleaning cached secret in openshift-authentication"

  if $KUBECTL get secret v4-0-config-system-router-certs -n openshift-authentication &>/dev/null; then
    $KUBECTL delete secret v4-0-config-system-router-certs -n openshift-authentication
    ok "Secret v4-0-config-system-router-certs deleted"
  else
    info "Secret not present (it will be recreated)"
  fi

  # ── STEP 10: Restart authentication ──
  step 10 "Restarting authentication-operator and oauth pods"

  if [[ "$FIX_IMAGEPULL" == true ]]; then
    info "Applying imagePullPolicy=IfNotPresent patch to authentication-operator..."
    $KUBECTL patch deployment authentication-operator -n openshift-authentication-operator \
      --type=json \
      -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' 2>/dev/null || true
  fi

  $KUBECTL delete pods --all -n openshift-authentication-operator 2>/dev/null || true
  info "Waiting for authentication-operator to be Running..."

  for i in $(seq 1 60); do
    READY=$($KUBECTL get pods -n openshift-authentication-operator \
      -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null || echo "false")
    if [[ "$READY" == "true" ]]; then
      ok "Authentication-operator Running"
      break
    fi
    POD_STATUS=$($KUBECTL get pods -n openshift-authentication-operator \
      -o jsonpath='{.items[0].status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || echo "")
    if [[ "$POD_STATUS" == "ImagePullBackOff" || "$POD_STATUS" == "ErrImagePull" ]]; then
      warn "ImagePullBackOff detected — applying IfNotPresent patch"
      $KUBECTL patch deployment authentication-operator -n openshift-authentication-operator \
        --type=json \
        -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' 2>/dev/null || true
    fi
    echo -n "."
    sleep 3
  done
  echo ""

  info "Restarting oauth pods..."
  $KUBECTL delete pods --all -n openshift-authentication 2>/dev/null || true

  info "Waiting for oauth pods to be ready (max 120s)..."
  for i in $(seq 1 40); do
    RUNNING=$($KUBECTL get pods -n openshift-authentication --no-headers 2>/dev/null | grep -c "Running" || echo 0)
    TOTAL=$($KUBECTL get pods -n openshift-authentication --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$RUNNING" -gt 0 && "$RUNNING" -eq "$TOTAL" ]]; then
      ok "Pod oauth Running ($RUNNING/$TOTAL)"
      break
    fi
    echo -n "."
    sleep 3
  done
  echo ""

  # ── STEP 11: Final OCP verification ──
  step 11 "Final verification"

  info "Waiting 60 seconds for operator reconciliation..."
  sleep 60

  divider
  info "ClusterOperators status:"
  divider

  ALL_OK=true
  for OP in authentication console ingress; do
    AVAILABLE=$($KUBECTL get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null || echo "Unknown")
    DEGRADED=$($KUBECTL get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].status}' 2>/dev/null || echo "Unknown")
    MSG=$($KUBECTL get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].message}' 2>/dev/null || echo "")

    if [[ "$AVAILABLE" == "True" && "$DEGRADED" == "False" ]]; then
      ok "$OP: Available=$AVAILABLE, Degraded=$DEGRADED ✅"
    else
      warn "$OP: Available=$AVAILABLE, Degraded=$DEGRADED"
      [[ -n "$MSG" ]] && echo "     Message: ${MSG:0:200}"
      ALL_OK=false
    fi
  done

  divider
  info "Certificate served by the router:"
  OAUTH_HOST=$($KUBECTL get route oauth-openshift -n openshift-authentication -o jsonpath='{.spec.host}' 2>/dev/null || echo "oauth-openshift.$APPS_DOMAIN")
  echo | openssl s_client -connect "$OAUTH_HOST":443 -servername "$OAUTH_HOST" 2>/dev/null | \
    openssl x509 -noout -dates -subject 2>/dev/null || warn "Unable to verify via TLS"

fi  # end OCP


# ═══════════════════════════════════════════════════════════════════════════════
#  RKE2 FLOW
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "rke2" ]]; then

  # Detect RKE2 environment
  IS_SERVER_NODE=false
  RKE2_TLS_DIR="$RKE2_DATA_DIR/server/tls"
  [[ -d "$RKE2_TLS_DIR" ]] && IS_SERVER_NODE=true

  RKE2_SERVICE=""
  if systemctl list-units --type=service 2>/dev/null | grep -q rke2-server; then
    RKE2_SERVICE="rke2-server"
  elif systemctl list-units --type=service 2>/dev/null | grep -q rke2-agent; then
    RKE2_SERVICE="rke2-agent"
  fi

  if [[ "$IS_SERVER_NODE" == true ]]; then
    ok "RKE2 server node detected: $RKE2_TLS_DIR"
  else
    warn "This is not an RKE2 server node — control plane operations are not available"
  fi
  [[ -n "$RKE2_SERVICE" ]] && ok "Service: $RKE2_SERVICE"

  # ── STEP 1: Check control plane certificates ──
  step 1 "Checking control plane certificates"

  EXPIRED_CERTS=()
  EXPIRING_CERTS=()

  if [[ "$IS_SERVER_NODE" == true ]]; then
    declare -A CP_CERTS=(
      ["kube-apiserver"]="$RKE2_TLS_DIR/serving-kube-apiserver.crt"
      ["kube-apiserver-client"]="$RKE2_TLS_DIR/client-kube-apiserver.crt"
      ["kube-controller-manager"]="$RKE2_TLS_DIR/client-controller-manager.crt"
      ["kube-scheduler"]="$RKE2_TLS_DIR/client-scheduler.crt"
      ["kube-proxy"]="$RKE2_TLS_DIR/client-kube-proxy.crt"
      ["cloud-controller"]="$RKE2_TLS_DIR/client-cloud-controller.crt"
      ["etcd-server"]="$RKE2_TLS_DIR/etcd/server-client.crt"
      ["etcd-peer"]="$RKE2_TLS_DIR/etcd/peer-server-client.crt"
      ["admin-kubeconfig"]="$RKE2_TLS_DIR/client-admin.crt"
      ["auth-proxy"]="$RKE2_TLS_DIR/client-auth-proxy.crt"
      ["kubelet"]="$RKE2_TLS_DIR/serving-kubelet.crt"
      ["request-header-ca"]="$RKE2_TLS_DIR/request-header-ca.crt"
      ["server-ca"]="$RKE2_TLS_DIR/server-ca.crt"
      ["client-ca"]="$RKE2_TLS_DIR/client-ca.crt"
    )

    for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
      CERT_PATH="${CP_CERTS[$CERT_NAME]}"
      set +e
      check_cert_file "$CERT_PATH" "$CERT_NAME"
      RET=$?
      set -e
      case $RET in
        2) EXPIRED_CERTS+=("$CERT_NAME") ;;
        3) EXPIRING_CERTS+=("$CERT_NAME") ;;
      esac
    done

    divider
    if [[ ${#EXPIRED_CERTS[@]} -gt 0 ]]; then
      err "EXPIRED certificates: ${EXPIRED_CERTS[*]}"
    fi
    if [[ ${#EXPIRING_CERTS[@]} -gt 0 ]]; then
      warn "Expiring soon (<${WARN_DAYS} days): ${EXPIRING_CERTS[*]}"
    fi
    if [[ ${#EXPIRED_CERTS[@]} -eq 0 && ${#EXPIRING_CERTS[@]} -eq 0 ]]; then
      ok "All control plane certificates are valid"
    fi
  else
    info "Skipping — this is not an RKE2 server node"
  fi

  # ── STEP 2: Check ingress certificates ──
  step 2 "Checking ingress certificates"

  INGRESS_TYPE="unknown"
  INGRESS_NS=""
  INGRESS_EXPIRED=false
  TLS_SECRETS=""

  if [[ "$CLUSTER_ACCESS" == true ]]; then
    if $KUBECTL get deployment -n kube-system rke2-ingress-nginx-controller &>/dev/null; then
      INGRESS_TYPE="nginx"; INGRESS_NS="kube-system"
    elif $KUBECTL get deployment -n ingress-nginx ingress-nginx-controller &>/dev/null; then
      INGRESS_TYPE="nginx"; INGRESS_NS="ingress-nginx"
    elif $KUBECTL get deployment -n kube-system traefik &>/dev/null; then
      INGRESS_TYPE="traefik"; INGRESS_NS="kube-system"
    fi
    [[ "$INGRESS_TYPE" != "unknown" ]] && ok "Ingress controller: $INGRESS_TYPE ($INGRESS_NS)"

    info "Searching TLS secrets..."
    TLS_SECRETS=$($KUBECTL get secrets -A -o json 2>/dev/null | \
      jq -r '.items[] | select(.type=="kubernetes.io/tls") |
      "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")

    if [[ -n "$TLS_SECRETS" ]]; then
      while IFS='/' read -r NS SECRET; do
        set +e
        check_cert_secret "$NS" "$SECRET" "tls:$NS/$SECRET"
        RET=$?
        set -e
        [[ $RET -eq 2 ]] && INGRESS_EXPIRED=true
      done <<< "$TLS_SECRETS"
    else
      info "No TLS secrets found"
    fi
  fi

  # ── check-only: exit ──
  if [[ "$CHECK_ONLY" == true ]]; then
    divider
    info "Check-only mode — no changes applied."
    if [[ ${#EXPIRED_CERTS[@]} -gt 0 || "$INGRESS_EXPIRED" == true ]]; then
      echo -e "\nSummary: ${RED}EXPIRED CERTIFICATES DETECTED${NC}"
    elif [[ ${#EXPIRING_CERTS[@]} -gt 0 ]]; then
      echo -e "\nSummary: ${YELLOW}CERTIFICATES EXPIRING SOON${NC}"
    else
      echo -e "\nSummary: ${GREEN}ALL CERTIFICATES VALID${NC}"
    fi
    echo ""
    echo "To apply fixes:"
    echo "  $0 --platform=rke2 --fix-controlplane"
    echo "  $0 --platform=rke2 --fix-ingress --ingress-domain=apps.example.com"
    echo "  $0 --platform=rke2 --fix-all"
    exit 0
  fi

  # ── auto mode: proceed only if needed ──
  if [[ "$AUTO_MODE" == true ]]; then
    NEEDS_RENEWAL=false

    # Check control plane: expired or expiring within the threshold
    if [[ "$IS_SERVER_NODE" == true && "$FIX_CONTROLPLANE" == true ]]; then
      if [[ ${#EXPIRED_CERTS[@]} -gt 0 ]]; then
        NEEDS_RENEWAL=true
        warn "Auto mode: ${#EXPIRED_CERTS[@]} control plane certificates EXPIRED — proceeding with renewal"
      else
        # Check whether any certificate expires within AUTO_THRESHOLD_DAYS
        for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
          CERT_PATH="${CP_CERTS[$CERT_NAME]}"
          [[ ! -f "$CERT_PATH" ]] && continue
          NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
          [[ -z "$NOT_AFTER" ]] && continue
          EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
          DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
          if (( DAYS_LEFT <= AUTO_THRESHOLD_DAYS )); then
            NEEDS_RENEWAL=true
            warn "Auto mode: $CERT_NAME expires in $DAYS_LEFT days (threshold: ${AUTO_THRESHOLD_DAYS} days) — proceeding with renewal"
            break
          fi
        done
      fi
    fi

    # Check ingress
    if [[ "$FIX_INGRESS" == true ]]; then
      if [[ "$INGRESS_EXPIRED" == true ]]; then
        NEEDS_RENEWAL=true
        warn "Auto mode: ingress certificates EXPIRED — proceeding with renewal"
      elif [[ -n "$TLS_SECRETS" ]]; then
        while IFS='/' read -r NS SECRET; do
          CERT_DATA=$($KUBECTL get secret "$SECRET" -n "$NS" -o jsonpath='{.data.tls\.crt}' 2>/dev/null || echo "")
          [[ -z "$CERT_DATA" ]] && continue
          NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
          [[ -z "$NOT_AFTER" ]] && continue
          EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
          DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
          if (( DAYS_LEFT <= AUTO_THRESHOLD_DAYS )); then
            NEEDS_RENEWAL=true
            warn "Auto mode: secret $NS/$SECRET expires in $DAYS_LEFT days (threshold: ${AUTO_THRESHOLD_DAYS} days) — proceeding with renewal"
            break
          fi
        done <<< "$TLS_SECRETS"
      fi
    fi

    if [[ "$NEEDS_RENEWAL" == false ]]; then
      ok "Auto mode: no certificate expires within ${AUTO_THRESHOLD_DAYS} days — no action needed"
      exit 0
    fi
  fi

  # Check that an action was specified
  if [[ "$FIX_CONTROLPLANE" == false && "$FIX_INGRESS" == false ]]; then
    warn "No action specified. Use --fix-controlplane, --fix-ingress, or --fix-all"
    exit 0
  fi

  # ── STEP 3: Backup ──
  step 3 "Backing up certificates"

  BACKUP_DIR="/root/rke2-certs-backup-$(date +%Y%m%d-%H%M%S)"

  if [[ "$FIX_CONTROLPLANE" == true && "$IS_SERVER_NODE" == true ]]; then
    mkdir -p "$BACKUP_DIR/tls"
    cp -a "$RKE2_TLS_DIR/" "$BACKUP_DIR/tls/" 2>/dev/null || warn "Backup parziale"
    for KC in /etc/rancher/rke2/rke2.yaml; do
      [[ -f "$KC" ]] && cp "$KC" "$BACKUP_DIR/" 2>/dev/null || true
    done
    ok "Control plane backup: $BACKUP_DIR"
  fi

  if [[ "$FIX_INGRESS" == true && "$CLUSTER_ACCESS" == true && -n "$TLS_SECRETS" ]]; then
    mkdir -p "$BACKUP_DIR/ingress-secrets"
    while IFS='/' read -r NS SECRET; do
      $KUBECTL get secret "$SECRET" -n "$NS" -o yaml > "$BACKUP_DIR/ingress-secrets/${NS}_${SECRET}.yaml" 2>/dev/null || true
    done <<< "$TLS_SECRETS"
    ok "Ingress secrets backup: $BACKUP_DIR/ingress-secrets/"
  fi

  # ── STEP 4: Fix control plane ──
  if [[ "$FIX_CONTROLPLANE" == true ]]; then
    step 4 "Regenerating control plane certificates"

    if [[ "$IS_SERVER_NODE" == false ]]; then
      err "This is not an RKE2 server node — unable to regenerate the control plane"
      exit 1
    fi
    if [[ "$RKE2_SERVICE" != "rke2-server" ]]; then
      err "rke2-server service not found"
      exit 1
    fi

    if [[ ${#EXPIRED_CERTS[@]} -gt 0 ]]; then
      info "Removing expired certificates..."
      for CERT_NAME in "${EXPIRED_CERTS[@]}"; do
        CERT_PATH="${CP_CERTS[$CERT_NAME]:-}"
        KEY_PATH="${CERT_PATH%.crt}.key"
        if [[ -n "$CERT_PATH" && -f "$CERT_PATH" ]]; then
          info "Removing: $CERT_NAME"
          rm -f "$CERT_PATH"
          [[ -f "$KEY_PATH" ]] && rm -f "$KEY_PATH"
        fi
      done
    else
      info "Forcing regeneration of all non-CA certificates..."
      for CERT_NAME in "${!CP_CERTS[@]}"; do
        CERT_PATH="${CP_CERTS[$CERT_NAME]}"
        if [[ "$CERT_NAME" == *"-ca"* ]]; then
          info "Keeping CA: $CERT_NAME"
          continue
        fi
        if [[ -f "$CERT_PATH" ]]; then
          info "Removing: $CERT_NAME"
          rm -f "$CERT_PATH"
          KEY_PATH="${CERT_PATH%.crt}.key"
          [[ -f "$KEY_PATH" ]] && rm -f "$KEY_PATH"
        fi
      done
    fi
    ok "Certificates removed"

    info "Restarting rke2-server..."
    warn "The cluster will be temporarily unavailable"
    systemctl restart rke2-server

    info "Waiting for restart (max 180s)..."
    for i in $(seq 1 60); do
      if systemctl is-active rke2-server &>/dev/null && $KUBECTL get nodes &>/dev/null 2>&1; then
        ok "rke2-server active and apiserver reachable"
        break
      fi
      echo -n "."
      sleep 3
    done
    echo ""

    if ! systemctl is-active rke2-server &>/dev/null; then
      err "rke2-server did not restart — check: journalctl -u rke2-server -f"
      err "Backup at: $BACKUP_DIR"
      exit 1
    fi

    info "Checking new certificates..."
    NEW_EXPIRED=0
    for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
      CERT_PATH="${CP_CERTS[$CERT_NAME]}"
      set +e
      check_cert_file "$CERT_PATH" "$CERT_NAME"
      RET=$?
      set -e
      [[ $RET -eq 2 ]] && ((NEW_EXPIRED++))
    done

    if [[ $NEW_EXPIRED -eq 0 ]]; then
      ok "All control plane certificates regenerated successfully"
    else
      err "$NEW_EXPIRED certificates still expired"
    fi
  fi

  # ── STEP 5: Fix ingress ──
  UPDATED_SECRETS=0
  if [[ "$FIX_INGRESS" == true ]]; then
    STEP_N=5; [[ "$FIX_CONTROLPLANE" == false ]] && STEP_N=4
    step $STEP_N "Regenerating ingress certificate"

    if [[ "$CLUSTER_ACCESS" == false ]]; then
      err "Cluster access is not available"
      exit 1
    fi

    # Detect domain
    if [[ -z "$INGRESS_DOMAIN" ]]; then
      info "Auto-detecting ingress domain..."
      DETECTED=$($KUBECTL get ingress -A -o json 2>/dev/null | \
        jq -r '.items[].spec.rules[]?.host // empty' 2>/dev/null | \
        sed 's/^[^.]*\.//' | sort -u | head -1 || echo "")
      [[ -n "$DETECTED" ]] && INGRESS_DOMAIN="$DETECTED" && info "Detected domain: $INGRESS_DOMAIN"
    fi

    if [[ -z "$INGRESS_DOMAIN" ]]; then
      err "Domain not specified. Use --ingress-domain=apps.example.com"
      exit 1
    fi

    TMPDIR=$(mktemp -d)
    generate_selfsigned_cert "$INGRESS_DOMAIN" "$TMPDIR"

    if [[ -n "$TLS_SECRETS" ]]; then
      while IFS='/' read -r NS SECRET; do
        CERT_DATA=$($KUBECTL get secret "$SECRET" -n "$NS" -o jsonpath='{.data.tls\.crt}' 2>/dev/null || echo "")
        [[ -z "$CERT_DATA" ]] && continue
        NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
        EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)

        if (( EXPIRY_EPOCH < NOW_EPOCH )); then
          info "Updating: $NS/$SECRET"
          $KUBECTL create secret tls "$SECRET" \
            --cert="$TMPDIR/wildcard.crt" --key="$TMPDIR/wildcard.key" \
            -n "$NS" --dry-run=client -o yaml | $KUBECTL replace -f - 2>/dev/null && \
            ok "$NS/$SECRET updated" && ((UPDATED_SECRETS++)) || \
            warn "Unable to update $NS/$SECRET"
        fi
      done <<< "$TLS_SECRETS"
    fi

    if [[ $UPDATED_SECRETS -eq 0 ]]; then
      DEFAULT_NS="${INGRESS_NS:-kube-system}"
      $KUBECTL create secret tls default-tls-cert \
        --cert="$TMPDIR/wildcard.crt" --key="$TMPDIR/wildcard.key" \
        -n "$DEFAULT_NS" --dry-run=client -o yaml | $KUBECTL apply -f -
      ok "Secret $DEFAULT_NS/default-tls-cert created"
    fi

    info "Restarting ingress controller..."
    if [[ "$INGRESS_TYPE" == "nginx" ]]; then
      $KUBECTL rollout restart deployment/rke2-ingress-nginx-controller -n "$INGRESS_NS" 2>/dev/null || \
      $KUBECTL rollout restart deployment/ingress-nginx-controller -n "$INGRESS_NS" 2>/dev/null || \
      $KUBECTL delete pods -n "$INGRESS_NS" -l app.kubernetes.io/component=controller 2>/dev/null || true
    elif [[ "$INGRESS_TYPE" == "traefik" ]]; then
      $KUBECTL rollout restart deployment/traefik -n "$INGRESS_NS" 2>/dev/null || true
    else
      warn "Unknown ingress controller — restart it manually"
    fi
    ok "Ingress controller restarted"
    rm -rf "$TMPDIR"
  fi

  # ── Final RKE2 verification ──
  FINAL_N=6
  [[ "$FIX_CONTROLPLANE" == false || "$FIX_INGRESS" == false ]] && FINAL_N=5
  step $FINAL_N "Final verification"

  divider
  ALL_OK=true

  if [[ "$CLUSTER_ACCESS" == true ]]; then
    info "Node status:"
    $KUBECTL get nodes -o wide 2>/dev/null || true
    echo ""
  fi

  if [[ -n "$RKE2_SERVICE" ]]; then
    systemctl is-active "$RKE2_SERVICE" &>/dev/null && ok "$RKE2_SERVICE active" || { warn "$RKE2_SERVICE not active"; ALL_OK=false; }
  fi

  if [[ "$FIX_CONTROLPLANE" == true && "$IS_SERVER_NODE" == true ]]; then
    CP_EXP=0
    for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
      NOT_AFTER=$(openssl x509 -in "${CP_CERTS[$CERT_NAME]}" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
      EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
      (( EXPIRY_EPOCH < $(date +%s) )) && ((CP_EXP++))
    done
    if [[ $CP_EXP -eq 0 ]]; then
      ok "Control plane: all certificates valid ✅"
    else
      err "Control plane: $CP_EXP certificates still expired ❌"
      ALL_OK=false
    fi
  fi

  if [[ "$FIX_INGRESS" == true ]]; then
    info "Ingress: $UPDATED_SECRETS secrets updated"
  fi

fi  # end RKE2


# ═══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
divider
if [[ "${ALL_OK:-true}" == true ]]; then
  echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  ✅ OPERATION COMPLETED SUCCESSFULLY!             ║${NC}"
  echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
else
  echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║  ⚠️  Completed with warnings — verify the status.             ║${NC}"
  if [[ "$PLATFORM" == "ocp" ]]; then
    echo -e "${YELLOW}║  Command: oc get co                                          ║${NC}"
  else
    echo -e "${YELLOW}║  Command: journalctl -u rke2-server -f                       ║${NC}"
  fi
  echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
fi

[[ -n "${BACKUP_DIR:-}" && -d "${BACKUP_DIR:-}" ]] && info "Backup: $BACKUP_DIR"
info "Script completed — $(date)"
