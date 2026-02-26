#!/bin/bash
###############################################################################
# fix-k8s-certs.sh
# Script unificato per verificare e rigenerare i certificati su cluster
# OpenShift (OCP) e RKE2.
#
# Il tipo di piattaforma viene rilevato automaticamente oppure può essere
# forzato con --platform=ocp|rke2.
#
# Uso: ./fix-k8s-certs.sh [OPZIONI]
#
# Opzioni comuni:
#   --kubeconfig=PATH         Path al kubeconfig (supporto multi-ambiente)
#   --platform=ocp|rke2       Forza la piattaforma (default: auto-detect)
#   --check-only              Solo verifica, nessuna modifica
#
# Opzioni OCP:
#   --force-selfsigned        Genera subito un self-signed senza attendere
#   --fix-imagepull           Patch IfNotPresent per cluster air-gapped
#
# Opzioni RKE2:
#   --fix-controlplane        Rigenera i certificati del control plane
#   --fix-ingress             Rigenera il certificato wildcard dell'ingress
#   --fix-all                 Equivalente a --fix-controlplane --fix-ingress
#   --ingress-domain=FQDN    Dominio wildcard per l'ingress
#   --rke2-data-dir=PATH     Directory dati RKE2 (default: /var/lib/rancher/rke2)
###############################################################################

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Colori e funzioni di output
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
err()     { echo -e "${RED}[ERRORE]${NC} $*"; }
step()    { echo -e "\n${GREEN}━━━ STEP $1 ━━━${NC} $2"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────────${NC}"; }
banner()  { echo -e "${BOLD}${CYAN}$*${NC}"; }

# ─────────────────────────────────────────────────────────────────────────────
# Help (prima di tutto, non richiede dipendenze)
# ─────────────────────────────────────────────────────────────────────────────
for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    cat <<'EOF'
Uso: fix-k8s-certs.sh [OPZIONI]

Opzioni comuni:
  --kubeconfig=PATH         Path al kubeconfig (supporto multi-ambiente)
  --platform=ocp|rke2       Forza la piattaforma (default: auto-detect)
  --check-only              Solo verifica certificati, nessuna modifica
  --auto                    Modalità non-interattiva (no input utente):
                            rinnova solo se il cert scade entro la soglia,
                            altrimenti esce senza modifiche. Ideale per cron.
  --auto-threshold=DAYS     Soglia in giorni per --auto (default: 7)

Opzioni OpenShift (OCP):
  --force-selfsigned        Genera subito un certificato self-signed
  --fix-imagepull           Patch imagePullPolicy=IfNotPresent (air-gapped)

Opzioni RKE2:
  --fix-controlplane        Rigenera i certificati del control plane
  --fix-ingress             Rigenera il certificato wildcard dell'ingress
  --fix-all                 Fix control plane + ingress
  --ingress-domain=FQDN    Dominio wildcard (es: apps.mycluster.it)
  --rke2-data-dir=PATH     Directory dati RKE2 (default: /var/lib/rancher/rke2)

Esempi:
  # OpenShift — auto-detect
  ./fix-k8s-certs.sh --kubeconfig=/path/to/ocp-prod.kubeconfig

  # OpenShift — air-gapped con self-signed forzato
  ./fix-k8s-certs.sh --kubeconfig=/path/to/ocp.kubeconfig --force-selfsigned --fix-imagepull

  # RKE2 — solo verifica
  ./fix-k8s-certs.sh --kubeconfig=/path/to/rke2-prod.yaml --check-only

  # RKE2 — fix completo
  ./fix-k8s-certs.sh --kubeconfig=/path/to/rke2.yaml --fix-all --ingress-domain=apps.example.com

  # Forza piattaforma
  ./fix-k8s-certs.sh --platform=rke2 --kubeconfig=/path/to/kubeconfig --fix-controlplane

  # Cron job: rinnova OCP solo se scade entro 7gg (default)
  ./fix-k8s-certs.sh --auto --kubeconfig=/path/to/ocp.kubeconfig

  # Cron job: rinnova OCP solo se scade entro 30gg
  ./fix-k8s-certs.sh --auto --auto-threshold=30 --kubeconfig=/path/to/ocp.kubeconfig

  # Cron job: rinnova RKE2 control plane + ingress
  ./fix-k8s-certs.sh --auto --kubeconfig=/path/to/rke2.yaml --fix-all --ingress-domain=apps.example.com
EOF
    exit 0
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Verifica dipendenze
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
  echo -e "${RED}[ERRORE]${NC} Tool obbligatori mancanti: ${MISSING_TOOLS[*]}"
  echo ""
  echo "  RHEL/CentOS/Fedora:  sudo dnf install -y jq openssl coreutils"
  echo "  Debian/Ubuntu:       sudo apt install -y jq openssl coreutils"
  echo "  SUSE/SLES:           sudo zypper install -y jq openssl coreutils"
  exit 1
fi

echo -e "${GREEN}[OK]${NC}    Tool obbligatori: ${REQUIRED_TOOLS[*]}"
if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
  echo -e "${YELLOW}[WARN]${NC}  Tool opzionali mancanti: ${MISSING_OPTIONAL[*]}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Parsing argomenti
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
    # Comuni
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
    *) err "Opzione sconosciuta: $1"; exit 1 ;;
  esac
done

# Validazione --auto-threshold
if [[ "$AUTO_MODE" == true ]]; then
  if ! [[ "$AUTO_THRESHOLD_DAYS" =~ ^[0-9]+$ ]] || [[ "$AUTO_THRESHOLD_DAYS" -lt 1 ]]; then
    err "--auto-threshold deve essere un numero intero positivo (ricevuto: '$AUTO_THRESHOLD_DAYS')"
    exit 1
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Kubeconfig
# ─────────────────────────────────────────────────────────────────────────────
if [[ -n "$KUBECONFIG_PATH" ]]; then
  if [[ ! -f "$KUBECONFIG_PATH" ]]; then
    err "Kubeconfig non trovato: $KUBECONFIG_PATH"
    exit 1
  fi
  export KUBECONFIG="$KUBECONFIG_PATH"
  ok "Kubeconfig: $KUBECONFIG_PATH"
elif [[ -n "${KUBECONFIG:-}" ]]; then
  info "Kubeconfig da env: $KUBECONFIG"
else
  # Auto-detect per RKE2
  for KC in /etc/rancher/rke2/rke2.yaml "$HOME/.kube/config"; do
    if [[ -f "$KC" ]]; then
      export KUBECONFIG="$KC"
      info "Kubeconfig auto-rilevato: $KC"
      break
    fi
  done
  if [[ -z "${KUBECONFIG:-}" ]]; then
    info "Kubeconfig: default (~/.kube/config)"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Rileva CLI disponibile (oc o kubectl)
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
  err "Nessun client Kubernetes trovato (oc o kubectl). Installane uno."
  exit 1
fi
ok "CLI Kubernetes: $KUBECTL"

# Verifica connessione
CLUSTER_ACCESS=false
if $KUBECTL cluster-info &>/dev/null 2>&1; then
  CLUSTER_ACCESS=true
  ok "Connessione al cluster: attiva"
else
  # Per OCP prova oc whoami
  if [[ "$KUBECTL" == "oc" ]] && oc whoami &>/dev/null 2>&1; then
    CLUSTER_ACCESS=true
    ok "Connessione al cluster: attiva (oc)"
  else
    err "Impossibile connettersi al cluster. Verifica kubeconfig e connettività."
    exit 1
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Auto-detect piattaforma
# ─────────────────────────────────────────────────────────────────────────────
if [[ -z "$PLATFORM" ]]; then
  info "Rilevamento piattaforma..."

  # Metodo 1: risorse OCP-specifiche
  if $KUBECTL get clusteroperators &>/dev/null 2>&1; then
    PLATFORM="ocp"
  # Metodo 2: verifica nodi con label RKE2
  elif $KUBECTL get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' 2>/dev/null | grep -qi "containerd"; then
    # Verifica se è RKE2 guardando i pod
    if $KUBECTL get pods -n kube-system -l app.kubernetes.io/name=rke2 &>/dev/null 2>&1 || \
       [[ -d "$RKE2_DATA_DIR/server/tls" ]] || \
       systemctl list-units --type=service 2>/dev/null | grep -q rke2; then
      PLATFORM="rke2"
    fi
  fi

  # Metodo 3: filesystem locale
  if [[ -z "$PLATFORM" ]]; then
    if [[ -d "$RKE2_DATA_DIR/server/tls" ]]; then
      PLATFORM="rke2"
    fi
  fi

  if [[ -z "$PLATFORM" ]]; then
    err "Impossibile rilevare la piattaforma. Specifica --platform=ocp oppure --platform=rke2"
    exit 1
  fi
fi

# Validazione
case "$PLATFORM" in
  ocp|openshift)  PLATFORM="ocp" ;;
  rke2|rancher)   PLATFORM="rke2" ;;
  *)
    err "Piattaforma non supportata: $PLATFORM (usa: ocp, rke2)"
    exit 1
    ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Funzioni comuni
# ─────────────────────────────────────────────────────────────────────────────
check_cert_file() {
  local CERT_PATH="$1"
  local CERT_NAME="$2"

  if [[ ! -f "$CERT_PATH" ]]; then
    warn "$CERT_NAME: file non trovato ($CERT_PATH)"
    return 1
  fi

  local NOT_AFTER SUBJECT EXPIRY_EPOCH NOW_EPOCH DAYS_LEFT
  NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
  SUBJECT=$(openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")

  if [[ -z "$NOT_AFTER" ]]; then
    warn "$CERT_NAME: impossibile leggere il certificato"
    return 1
  fi

  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if (( DAYS_LEFT < 0 )); then
    err "$CERT_NAME: SCADUTO da $(( DAYS_LEFT * -1 )) giorni ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 2
  elif (( DAYS_LEFT < WARN_DAYS )); then
    warn "$CERT_NAME: scade tra $DAYS_LEFT giorni ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 3
  else
    ok "$CERT_NAME: valido, scade tra $DAYS_LEFT giorni ($NOT_AFTER)"
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
    warn "$CERT_NAME: secret $SECRET_NAME non trovato in $NAMESPACE"
    return 1
  fi

  local NOT_AFTER EXPIRY_EPOCH NOW_EPOCH DAYS_LEFT SUBJECT
  NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
  SUBJECT=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")

  if [[ -z "$NOT_AFTER" ]]; then
    warn "$CERT_NAME: impossibile decodificare il certificato"
    return 1
  fi

  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if (( DAYS_LEFT < 0 )); then
    err "$CERT_NAME: SCADUTO da $(( DAYS_LEFT * -1 )) giorni ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 2
  elif (( DAYS_LEFT < WARN_DAYS )); then
    warn "$CERT_NAME: scade tra $DAYS_LEFT giorni ($NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 3
  else
    ok "$CERT_NAME: valido, scade tra $DAYS_LEFT giorni ($NOT_AFTER)"
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

  ok "Certificato self-signed generato (*.$DOMAIN, validità ${DAYS}gg)"
  openssl x509 -in "$OUTDIR/wildcard.crt" -noout -dates
}

# ═══════════════════════════════════════════════════════════════════════════════
#  AVVIO
# ═══════════════════════════════════════════════════════════════════════════════
divider
banner "fix-k8s-certs.sh — Piattaforma: ${PLATFORM^^} — $(date)"

if [[ "$AUTO_MODE" == true ]]; then
  info "Modalità: AUTO (non-interattiva, soglia rinnovo: ${AUTO_THRESHOLD_DAYS} giorni)"
fi

if [[ "$PLATFORM" == "ocp" ]]; then
  CLUSTER_USER=$($KUBECTL whoami 2>/dev/null || echo "N/A")
  CLUSTER_API=$($KUBECTL whoami --show-server 2>/dev/null || echo "N/A")
  info "Utente:  $CLUSTER_USER"
  info "Cluster: $CLUSTER_API"
else
  info "Cluster: $($KUBECTL cluster-info 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g' || echo 'N/A')"
fi
divider

# ═══════════════════════════════════════════════════════════════════════════════
#  FLUSSO OCP
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "ocp" ]]; then

  # ── STEP 1: Rileva dominio ──
  step 1 "Rilevamento dominio wildcard apps"

  APPS_DOMAIN=$($KUBECTL get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}' 2>/dev/null || true)
  if [[ -z "$APPS_DOMAIN" ]]; then
    APPS_DOMAIN=$($KUBECTL get route console -n openshift-console -o jsonpath='{.spec.host}' 2>/dev/null | sed 's/^console-openshift-console\.//')
  fi
  if [[ -z "$APPS_DOMAIN" ]]; then
    err "Impossibile determinare il dominio apps del cluster."
    exit 1
  fi
  ok "Dominio: $APPS_DOMAIN"
  WILDCARD_CN="*.$APPS_DOMAIN"

  # ── STEP 2: Verifica certificato ──
  step 2 "Verifica certificato attuale del router"

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
        ok "Il certificato è ancora valido (scade tra $DAYS_LEFT giorni: $NOT_AFTER)"

        if [[ "$CHECK_ONLY" == true ]]; then
          info "Modalità check-only — nessuna modifica."
          exit 0
        fi

        if [[ "$AUTO_MODE" == true ]]; then
          if (( DAYS_LEFT <= AUTO_THRESHOLD_DAYS )); then
            warn "Modalità auto: il certificato scade tra $DAYS_LEFT giorni (soglia: ${AUTO_THRESHOLD_DAYS}gg) — procedo al rinnovo"
          else
            ok "Modalità auto: il certificato scade tra $DAYS_LEFT giorni (soglia: ${AUTO_THRESHOLD_DAYS}gg) — nessun intervento necessario"
            exit 0
          fi
        else
          echo ""
          read -rp "Vuoi continuare comunque con la rigenerazione? (s/N) " REPLY
          if [[ ! "$REPLY" =~ ^[sSyY]$ ]]; then
            info "Operazione annullata."
            exit 0
          fi
        fi
      else
        warn "Certificato SCADUTO il $NOT_AFTER"
        if [[ "$AUTO_MODE" == true ]]; then
          info "Modalità auto: certificato scaduto — procedo al rinnovo"
        fi
      fi
    else
      warn "Impossibile decodificare il certificato attuale"
    fi
  else
    warn "Secret router-certs-default non trovato in openshift-ingress"
  fi

  # ── STEP 3: Stato operator ──
  step 3 "Stato attuale degli operator impattati"

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
    info "Modalità check-only — nessuna modifica applicata."
    exit 0
  fi

  # ── STEP 4: Elimina secret router ──
  step 4 "Eliminazione secret router-certs-default"

  if $KUBECTL get secret router-certs-default -n openshift-ingress &>/dev/null; then
    $KUBECTL delete secret router-certs-default -n openshift-ingress
    ok "Secret eliminato da openshift-ingress"
  else
    info "Secret già assente in openshift-ingress"
  fi

  # ── STEP 5: Riavvia ingress-operator ──
  step 5 "Riavvio ingress-operator"

  $KUBECTL delete pods --all -n openshift-ingress-operator 2>/dev/null || true
  info "Pod eliminati, attendo il restart..."
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

  # ── STEP 6: Attendi rigenerazione o forza self-signed ──
  step 6 "Attesa rigenerazione certificato"

  CERT_REGENERATED=false

  if [[ "$FORCE_SELFSIGNED" == false ]]; then
    info "Attendo che l'ingress-operator rigeneri il secret (max 60s)..."
    for i in $(seq 1 12); do
      if $KUBECTL get secret router-certs-default -n openshift-ingress &>/dev/null; then
        NEW_DATES=$($KUBECTL get secret router-certs-default -n openshift-ingress \
          -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates 2>/dev/null || true)
        if [[ -n "$NEW_DATES" ]]; then
          ok "Secret rigenerato automaticamente dall'operator"
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
    warn "Rigenerazione automatica non avvenuta — creo certificato self-signed"
    TMPDIR=$(mktemp -d)
    generate_selfsigned_cert "$APPS_DOMAIN" "$TMPDIR"

    $KUBECTL create secret tls router-certs-default \
      --cert="$TMPDIR/wildcard.crt" \
      --key="$TMPDIR/wildcard.key" \
      -n openshift-ingress
    ok "Secret router-certs-default creato"
    rm -rf "$TMPDIR"
  fi

  # ── STEP 7: Riavvia router pods ──
  step 7 "Riavvio router pods"

  $KUBECTL rollout restart deployment/router-default -n openshift-ingress 2>/dev/null || \
    $KUBECTL delete pods --all -n openshift-ingress 2>/dev/null || true
  info "Attendo che i router siano pronti..."
  $KUBECTL rollout status deployment/router-default -n openshift-ingress --timeout=120s 2>/dev/null || \
    warn "Timeout rollout router — potrebbe richiedere più tempo"
  ok "Router riavviati"

  # ── STEP 8: Propaga a config-managed ──
  step 8 "Propagazione certificato a openshift-config-managed"

  $KUBECTL delete secret router-certs-default -n openshift-config-managed 2>/dev/null || true
  $KUBECTL get secret router-certs-default -n openshift-ingress -o json | \
    jq '.metadata.namespace = "openshift-config-managed" |
        del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp, .metadata.managedFields)' | \
    $KUBECTL apply -f -
  ok "Secret copiato in openshift-config-managed"

  # ── STEP 9: Pulizia cache authentication ──
  step 9 "Pulizia secret cached in openshift-authentication"

  if $KUBECTL get secret v4-0-config-system-router-certs -n openshift-authentication &>/dev/null; then
    $KUBECTL delete secret v4-0-config-system-router-certs -n openshift-authentication
    ok "Secret v4-0-config-system-router-certs eliminato"
  else
    info "Secret non presente (verrà ricreato)"
  fi

  # ── STEP 10: Riavvia authentication ──
  step 10 "Riavvio authentication-operator e pod oauth"

  if [[ "$FIX_IMAGEPULL" == true ]]; then
    info "Applico patch imagePullPolicy=IfNotPresent su authentication-operator..."
    $KUBECTL patch deployment authentication-operator -n openshift-authentication-operator \
      --type=json \
      -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' 2>/dev/null || true
  fi

  $KUBECTL delete pods --all -n openshift-authentication-operator 2>/dev/null || true
  info "Attendo che l'authentication-operator sia Running..."

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
      warn "ImagePullBackOff rilevato — applico patch IfNotPresent"
      $KUBECTL patch deployment authentication-operator -n openshift-authentication-operator \
        --type=json \
        -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' 2>/dev/null || true
    fi
    echo -n "."
    sleep 3
  done
  echo ""

  info "Riavvio pod oauth..."
  $KUBECTL delete pods --all -n openshift-authentication 2>/dev/null || true

  info "Attendo che i pod oauth siano pronti (max 120s)..."
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

  # ── STEP 11: Verifica finale OCP ──
  step 11 "Verifica finale"

  info "Attendo 60 secondi per la riconciliazione degli operator..."
  sleep 60

  divider
  info "Stato ClusterOperators:"
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
      [[ -n "$MSG" ]] && echo "     Messaggio: ${MSG:0:200}"
      ALL_OK=false
    fi
  done

  divider
  info "Certificato servito dal router:"
  OAUTH_HOST=$($KUBECTL get route oauth-openshift -n openshift-authentication -o jsonpath='{.spec.host}' 2>/dev/null || echo "oauth-openshift.$APPS_DOMAIN")
  echo | openssl s_client -connect "$OAUTH_HOST":443 -servername "$OAUTH_HOST" 2>/dev/null | \
    openssl x509 -noout -dates -subject 2>/dev/null || warn "Impossibile verificare via TLS"

fi  # fine OCP


# ═══════════════════════════════════════════════════════════════════════════════
#  FLUSSO RKE2
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "rke2" ]]; then

  # Rileva ambiente RKE2
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
    ok "Nodo server RKE2 rilevato: $RKE2_TLS_DIR"
  else
    warn "Non siamo su un nodo server RKE2 — operazioni control plane non disponibili"
  fi
  [[ -n "$RKE2_SERVICE" ]] && ok "Servizio: $RKE2_SERVICE"

  # ── STEP 1: Verifica certificati control plane ──
  step 1 "Verifica certificati control plane"

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
      err "Certificati SCADUTI: ${EXPIRED_CERTS[*]}"
    fi
    if [[ ${#EXPIRING_CERTS[@]} -gt 0 ]]; then
      warn "In scadenza (<${WARN_DAYS}gg): ${EXPIRING_CERTS[*]}"
    fi
    if [[ ${#EXPIRED_CERTS[@]} -eq 0 && ${#EXPIRING_CERTS[@]} -eq 0 ]]; then
      ok "Tutti i certificati del control plane sono validi"
    fi
  else
    info "Skipping — non siamo su un nodo server RKE2"
  fi

  # ── STEP 2: Verifica certificati ingress ──
  step 2 "Verifica certificati ingress"

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

    info "Ricerca secret TLS..."
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
      info "Nessun secret TLS trovato"
    fi
  fi

  # ── check-only: termina ──
  if [[ "$CHECK_ONLY" == true ]]; then
    divider
    info "Modalità check-only — nessuna modifica applicata."
    if [[ ${#EXPIRED_CERTS[@]} -gt 0 || "$INGRESS_EXPIRED" == true ]]; then
      echo -e "\nRiepilogo: ${RED}CERTIFICATI SCADUTI RILEVATI${NC}"
    elif [[ ${#EXPIRING_CERTS[@]} -gt 0 ]]; then
      echo -e "\nRiepilogo: ${YELLOW}CERTIFICATI IN SCADENZA${NC}"
    else
      echo -e "\nRiepilogo: ${GREEN}TUTTI I CERTIFICATI VALIDI${NC}"
    fi
    echo ""
    echo "Per applicare i fix:"
    echo "  $0 --platform=rke2 --fix-controlplane"
    echo "  $0 --platform=rke2 --fix-ingress --ingress-domain=apps.example.com"
    echo "  $0 --platform=rke2 --fix-all"
    exit 0
  fi

  # ── auto mode: procedi solo se necessario ──
  if [[ "$AUTO_MODE" == true ]]; then
    NEEDS_RENEWAL=false

    # Controlla control plane: scaduti o in scadenza entro la soglia
    if [[ "$IS_SERVER_NODE" == true && "$FIX_CONTROLPLANE" == true ]]; then
      if [[ ${#EXPIRED_CERTS[@]} -gt 0 ]]; then
        NEEDS_RENEWAL=true
        warn "Modalità auto: ${#EXPIRED_CERTS[@]} certificati control plane SCADUTI — procedo al rinnovo"
      else
        # Verifica se qualcuno scade entro AUTO_THRESHOLD_DAYS
        for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
          CERT_PATH="${CP_CERTS[$CERT_NAME]}"
          [[ ! -f "$CERT_PATH" ]] && continue
          NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
          [[ -z "$NOT_AFTER" ]] && continue
          EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
          DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
          if (( DAYS_LEFT <= AUTO_THRESHOLD_DAYS )); then
            NEEDS_RENEWAL=true
            warn "Modalità auto: $CERT_NAME scade tra $DAYS_LEFT giorni (soglia: ${AUTO_THRESHOLD_DAYS}gg) — procedo al rinnovo"
            break
          fi
        done
      fi
    fi

    # Controlla ingress
    if [[ "$FIX_INGRESS" == true ]]; then
      if [[ "$INGRESS_EXPIRED" == true ]]; then
        NEEDS_RENEWAL=true
        warn "Modalità auto: certificati ingress SCADUTI — procedo al rinnovo"
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
            warn "Modalità auto: secret $NS/$SECRET scade tra $DAYS_LEFT giorni (soglia: ${AUTO_THRESHOLD_DAYS}gg) — procedo al rinnovo"
            break
          fi
        done <<< "$TLS_SECRETS"
      fi
    fi

    if [[ "$NEEDS_RENEWAL" == false ]]; then
      ok "Modalità auto: nessun certificato scade entro ${AUTO_THRESHOLD_DAYS} giorni — nessun intervento necessario"
      exit 0
    fi
  fi

  # Verifica che sia stata specificata un'azione
  if [[ "$FIX_CONTROLPLANE" == false && "$FIX_INGRESS" == false ]]; then
    warn "Nessuna azione specificata. Usa --fix-controlplane, --fix-ingress, o --fix-all"
    exit 0
  fi

  # ── STEP 3: Backup ──
  step 3 "Backup certificati"

  BACKUP_DIR="/root/rke2-certs-backup-$(date +%Y%m%d-%H%M%S)"

  if [[ "$FIX_CONTROLPLANE" == true && "$IS_SERVER_NODE" == true ]]; then
    mkdir -p "$BACKUP_DIR/tls"
    cp -a "$RKE2_TLS_DIR/" "$BACKUP_DIR/tls/" 2>/dev/null || warn "Backup parziale"
    for KC in /etc/rancher/rke2/rke2.yaml; do
      [[ -f "$KC" ]] && cp "$KC" "$BACKUP_DIR/" 2>/dev/null || true
    done
    ok "Backup control plane: $BACKUP_DIR"
  fi

  if [[ "$FIX_INGRESS" == true && "$CLUSTER_ACCESS" == true && -n "$TLS_SECRETS" ]]; then
    mkdir -p "$BACKUP_DIR/ingress-secrets"
    while IFS='/' read -r NS SECRET; do
      $KUBECTL get secret "$SECRET" -n "$NS" -o yaml > "$BACKUP_DIR/ingress-secrets/${NS}_${SECRET}.yaml" 2>/dev/null || true
    done <<< "$TLS_SECRETS"
    ok "Backup ingress secrets: $BACKUP_DIR/ingress-secrets/"
  fi

  # ── STEP 4: Fix control plane ──
  if [[ "$FIX_CONTROLPLANE" == true ]]; then
    step 4 "Rigenerazione certificati control plane"

    if [[ "$IS_SERVER_NODE" == false ]]; then
      err "Non siamo su un nodo server RKE2 — impossibile rigenerare il control plane"
      exit 1
    fi
    if [[ "$RKE2_SERVICE" != "rke2-server" ]]; then
      err "Servizio rke2-server non trovato"
      exit 1
    fi

    if [[ ${#EXPIRED_CERTS[@]} -gt 0 ]]; then
      info "Rimozione certificati scaduti..."
      for CERT_NAME in "${EXPIRED_CERTS[@]}"; do
        CERT_PATH="${CP_CERTS[$CERT_NAME]:-}"
        KEY_PATH="${CERT_PATH%.crt}.key"
        if [[ -n "$CERT_PATH" && -f "$CERT_PATH" ]]; then
          info "Rimuovo: $CERT_NAME"
          rm -f "$CERT_PATH"
          [[ -f "$KEY_PATH" ]] && rm -f "$KEY_PATH"
        fi
      done
    else
      info "Forzo la rigenerazione di tutti i certificati non-CA..."
      for CERT_NAME in "${!CP_CERTS[@]}"; do
        CERT_PATH="${CP_CERTS[$CERT_NAME]}"
        if [[ "$CERT_NAME" == *"-ca"* ]]; then
          info "Mantengo CA: $CERT_NAME"
          continue
        fi
        if [[ -f "$CERT_PATH" ]]; then
          info "Rimuovo: $CERT_NAME"
          rm -f "$CERT_PATH"
          KEY_PATH="${CERT_PATH%.crt}.key"
          [[ -f "$KEY_PATH" ]] && rm -f "$KEY_PATH"
        fi
      done
    fi
    ok "Certificati rimossi"

    info "Riavvio rke2-server..."
    warn "Il cluster sarà temporaneamente non disponibile"
    systemctl restart rke2-server

    info "Attendo il riavvio (max 180s)..."
    for i in $(seq 1 60); do
      if systemctl is-active rke2-server &>/dev/null && $KUBECTL get nodes &>/dev/null 2>&1; then
        ok "rke2-server attivo e apiserver raggiungibile"
        break
      fi
      echo -n "."
      sleep 3
    done
    echo ""

    if ! systemctl is-active rke2-server &>/dev/null; then
      err "rke2-server non ripartito — controlla: journalctl -u rke2-server -f"
      err "Backup in: $BACKUP_DIR"
      exit 1
    fi

    info "Verifica nuovi certificati..."
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
      ok "Tutti i certificati del control plane rigenerati con successo"
    else
      err "$NEW_EXPIRED certificati ancora scaduti"
    fi
  fi

  # ── STEP 5: Fix ingress ──
  UPDATED_SECRETS=0
  if [[ "$FIX_INGRESS" == true ]]; then
    STEP_N=5; [[ "$FIX_CONTROLPLANE" == false ]] && STEP_N=4
    step $STEP_N "Rigenerazione certificato ingress"

    if [[ "$CLUSTER_ACCESS" == false ]]; then
      err "Accesso al cluster non disponibile"
      exit 1
    fi

    # Rileva dominio
    if [[ -z "$INGRESS_DOMAIN" ]]; then
      info "Rilevamento automatico dominio ingress..."
      DETECTED=$($KUBECTL get ingress -A -o json 2>/dev/null | \
        jq -r '.items[].spec.rules[]?.host // empty' 2>/dev/null | \
        sed 's/^[^.]*\.//' | sort -u | head -1 || echo "")
      [[ -n "$DETECTED" ]] && INGRESS_DOMAIN="$DETECTED" && info "Dominio rilevato: $INGRESS_DOMAIN"
    fi

    if [[ -z "$INGRESS_DOMAIN" ]]; then
      err "Dominio non specificato. Usa --ingress-domain=apps.example.com"
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
          info "Aggiornamento: $NS/$SECRET"
          $KUBECTL create secret tls "$SECRET" \
            --cert="$TMPDIR/wildcard.crt" --key="$TMPDIR/wildcard.key" \
            -n "$NS" --dry-run=client -o yaml | $KUBECTL replace -f - 2>/dev/null && \
            ok "$NS/$SECRET aggiornato" && ((UPDATED_SECRETS++)) || \
            warn "Impossibile aggiornare $NS/$SECRET"
        fi
      done <<< "$TLS_SECRETS"
    fi

    if [[ $UPDATED_SECRETS -eq 0 ]]; then
      DEFAULT_NS="${INGRESS_NS:-kube-system}"
      $KUBECTL create secret tls default-tls-cert \
        --cert="$TMPDIR/wildcard.crt" --key="$TMPDIR/wildcard.key" \
        -n "$DEFAULT_NS" --dry-run=client -o yaml | $KUBECTL apply -f -
      ok "Secret $DEFAULT_NS/default-tls-cert creato"
    fi

    info "Riavvio ingress controller..."
    if [[ "$INGRESS_TYPE" == "nginx" ]]; then
      $KUBECTL rollout restart deployment/rke2-ingress-nginx-controller -n "$INGRESS_NS" 2>/dev/null || \
      $KUBECTL rollout restart deployment/ingress-nginx-controller -n "$INGRESS_NS" 2>/dev/null || \
      $KUBECTL delete pods -n "$INGRESS_NS" -l app.kubernetes.io/component=controller 2>/dev/null || true
    elif [[ "$INGRESS_TYPE" == "traefik" ]]; then
      $KUBECTL rollout restart deployment/traefik -n "$INGRESS_NS" 2>/dev/null || true
    else
      warn "Ingress controller sconosciuto — riavvia manualmente"
    fi
    ok "Ingress controller riavviato"
    rm -rf "$TMPDIR"
  fi

  # ── Verifica finale RKE2 ──
  FINAL_N=6
  [[ "$FIX_CONTROLPLANE" == false || "$FIX_INGRESS" == false ]] && FINAL_N=5
  step $FINAL_N "Verifica finale"

  divider
  ALL_OK=true

  if [[ "$CLUSTER_ACCESS" == true ]]; then
    info "Stato nodi:"
    $KUBECTL get nodes -o wide 2>/dev/null || true
    echo ""
  fi

  if [[ -n "$RKE2_SERVICE" ]]; then
    systemctl is-active "$RKE2_SERVICE" &>/dev/null && ok "$RKE2_SERVICE attivo" || { warn "$RKE2_SERVICE non attivo"; ALL_OK=false; }
  fi

  if [[ "$FIX_CONTROLPLANE" == true && "$IS_SERVER_NODE" == true ]]; then
    CP_EXP=0
    for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
      NOT_AFTER=$(openssl x509 -in "${CP_CERTS[$CERT_NAME]}" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
      EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
      (( EXPIRY_EPOCH < $(date +%s) )) && ((CP_EXP++))
    done
    if [[ $CP_EXP -eq 0 ]]; then
      ok "Control plane: tutti i certificati validi ✅"
    else
      err "Control plane: $CP_EXP certificati ancora scaduti ❌"
      ALL_OK=false
    fi
  fi

  if [[ "$FIX_INGRESS" == true ]]; then
    info "Ingress: $UPDATED_SECRETS secret aggiornati"
  fi

fi  # fine RKE2


# ═══════════════════════════════════════════════════════════════════════════════
#  RIEPILOGO FINALE
# ═══════════════════════════════════════════════════════════════════════════════
divider
if [[ "${ALL_OK:-true}" == true ]]; then
  echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  ✅ OPERAZIONE COMPLETATA CON SUCCESSO!           ║${NC}"
  echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
else
  echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║  ⚠️  Completato con avvertimenti — verifica lo stato.         ║${NC}"
  if [[ "$PLATFORM" == "ocp" ]]; then
    echo -e "${YELLOW}║  Comando: oc get co                                          ║${NC}"
  else
    echo -e "${YELLOW}║  Comando: journalctl -u rke2-server -f                       ║${NC}"
  fi
  echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
fi

[[ -n "${BACKUP_DIR:-}" && -d "${BACKUP_DIR:-}" ]] && info "Backup: $BACKUP_DIR"
info "Script completato — $(date)"
