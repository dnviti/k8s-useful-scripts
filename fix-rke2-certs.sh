#!/bin/bash
###############################################################################
# fix-rke2-certs.sh
# Script per verificare e rigenerare i certificati di un cluster RKE2.
# Gestisce sia i certificati del control plane che quelli dell'ingress.
#
# Uso: ./fix-rke2-certs.sh [OPZIONI]
#
#   --check-only          Solo verifica, nessuna modifica
#   --fix-controlplane    Rigenera i certificati del control plane (richiede
#                         accesso SSH/root ai nodi server)
#   --fix-ingress         Rigenera il certificato wildcard dell'ingress
#   --ingress-domain FQDN Dominio wildcard per l'ingress (es: apps.mycluster.it)
#   --fix-all             Equivalente a --fix-controlplane --fix-ingress
#   --kubeconfig PATH     Path al kubeconfig (default: auto-detect)
#   --rke2-data-dir PATH  Directory dati RKE2 (default: /var/lib/rancher/rke2)
#
# Il script deve essere eseguito su un nodo server RKE2 per le operazioni
# sul control plane, oppure da remoto con kubeconfig per le operazioni ingress.
###############################################################################

set -euo pipefail

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Help rapido (prima del check dipendenze)
for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    echo "Uso: $0 [OPZIONI]"
    echo ""
    echo "Opzioni:"
    echo "  --check-only                Solo verifica certificati, nessuna modifica"
    echo "  --fix-controlplane          Rigenera i certificati del control plane"
    echo "  --fix-ingress               Rigenera il certificato wildcard dell'ingress"
    echo "  --fix-all                   Fix control plane + ingress"
    echo "  --ingress-domain=FQDN       Dominio wildcard (es: apps.mycluster.it)"
    echo "  --kubeconfig=PATH           Path al kubeconfig (supporto multi-ambiente)"
    echo "  --rke2-data-dir=PATH        Directory dati RKE2 (default: /var/lib/rancher/rke2)"
    echo ""
    echo "Esempi:"
    echo "  $0 --check-only --kubeconfig=/path/to/rke2-prod.yaml"
    echo "  $0 --fix-controlplane --kubeconfig=/path/to/rke2-dev.yaml"
    echo "  $0 --fix-all --kubeconfig=/path/to/rke2.yaml --ingress-domain=apps.example.com"
    exit 0
  fi
done

###############################################################################
# Verifica dipendenze
###############################################################################
REQUIRED_TOOLS=(openssl jq date sed grep awk tr mktemp cat)
OPTIONAL_TOOLS=(kubectl crictl systemctl)
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
  echo -e "${RED}[ERRORE]${NC} Installa i tool mancanti prima di eseguire lo script."
  echo ""
  echo "  Esempio (RHEL/CentOS/Fedora):"
  echo "    sudo dnf install -y jq openssl coreutils"
  echo ""
  echo "  Esempio (Debian/Ubuntu):"
  echo "    sudo apt install -y jq openssl coreutils"
  echo ""
  echo "  Esempio (SUSE/SLES):"
  echo "    sudo zypper install -y jq openssl coreutils"
  exit 1
fi

echo -e "${GREEN}[OK]${NC}    Tool obbligatori presenti: ${REQUIRED_TOOLS[*]}"

if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
  echo -e "${YELLOW}[WARN]${NC}  Tool opzionali mancanti: ${MISSING_OPTIONAL[*]}"
  echo -e "${YELLOW}[WARN]${NC}  Alcune funzionalità potrebbero non essere disponibili."
else
  echo -e "${GREEN}[OK]${NC}    Tool opzionali presenti: ${OPTIONAL_TOOLS[*]}"
fi

###############################################################################
# Parsing argomenti
###############################################################################
CHECK_ONLY=false
FIX_CONTROLPLANE=false
FIX_INGRESS=false
INGRESS_DOMAIN=""
KUBECONFIG_PATH=""
RKE2_DATA_DIR="/var/lib/rancher/rke2"
CERT_VALIDITY_DAYS=730
WARN_DAYS=30

while [[ $# -gt 0 ]]; do
  case $1 in
    --check-only)           CHECK_ONLY=true; shift ;;
    --fix-controlplane)     FIX_CONTROLPLANE=true; shift ;;
    --fix-ingress)          FIX_INGRESS=true; shift ;;
    --fix-all)              FIX_CONTROLPLANE=true; FIX_INGRESS=true; shift ;;
    --ingress-domain=*)     INGRESS_DOMAIN="${1#*=}"; shift ;;
    --ingress-domain)       INGRESS_DOMAIN="${2:-}"; shift 2 ;;
    --kubeconfig=*)         KUBECONFIG_PATH="${1#*=}"; shift ;;
    --kubeconfig)           KUBECONFIG_PATH="${2:-}"; shift 2 ;;
    --rke2-data-dir=*)      RKE2_DATA_DIR="${1#*=}"; shift ;;
    --rke2-data-dir)        RKE2_DATA_DIR="${2:-}"; shift 2 ;;
    -h|--help)            exit 0 ;;
    *) echo "Opzione sconosciuta: $1"; exit 1 ;;
  esac
done

###############################################################################
# Funzioni utility
###############################################################################
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERRORE]${NC} $*"; }
step()    { echo -e "\n${GREEN}━━━ STEP $1 ━━━${NC} $2"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────────${NC}"; }

check_cert_file() {
  local CERT_PATH="$1"
  local CERT_NAME="$2"

  if [[ ! -f "$CERT_PATH" ]]; then
    warn "$CERT_NAME: file non trovato ($CERT_PATH)"
    return 1
  fi

  local NOT_AFTER NOT_BEFORE SUBJECT EXPIRY_EPOCH NOW_EPOCH DAYS_LEFT
  NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
  NOT_BEFORE=$(openssl x509 -in "$CERT_PATH" -noout -startdate 2>/dev/null | cut -d= -f2 || echo "")
  SUBJECT=$(openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")

  if [[ -z "$NOT_AFTER" ]]; then
    warn "$CERT_NAME: impossibile leggere il certificato"
    return 1
  fi

  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if (( DAYS_LEFT < 0 )); then
    err "$CERT_NAME: SCADUTO da $(( DAYS_LEFT * -1 )) giorni (scadenza: $NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 2
  elif (( DAYS_LEFT < WARN_DAYS )); then
    warn "$CERT_NAME: scade tra $DAYS_LEFT giorni (scadenza: $NOT_AFTER)"
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
  local KUBECTL="$4"

  local CERT_DATA
  CERT_DATA=$($KUBECTL get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' 2>/dev/null || echo "")

  if [[ -z "$CERT_DATA" ]]; then
    warn "$CERT_NAME: secret $SECRET_NAME non trovato in $NAMESPACE"
    return 1
  fi

  local NOT_AFTER EXPIRY_EPOCH NOW_EPOCH DAYS_LEFT SUBJECT
  NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
  SUBJECT=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")

  if [[ -z "$NOT_AFTER" ]]; then
    warn "$CERT_NAME: impossibile decodificare il certificato dal secret"
    return 1
  fi

  EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if (( DAYS_LEFT < 0 )); then
    err "$CERT_NAME: SCADUTO da $(( DAYS_LEFT * -1 )) giorni (scadenza: $NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 2
  elif (( DAYS_LEFT < WARN_DAYS )); then
    warn "$CERT_NAME: scade tra $DAYS_LEFT giorni (scadenza: $NOT_AFTER)"
    echo "     Subject: $SUBJECT"
    return 3
  else
    ok "$CERT_NAME: valido, scade tra $DAYS_LEFT giorni ($NOT_AFTER)"
    return 0
  fi
}

###############################################################################
# Pre-flight
###############################################################################
divider
info "Avvio fix-rke2-certs.sh — $(date)"
divider

# Rileva kubectl
KUBECTL=""
if command -v kubectl &>/dev/null; then
  KUBECTL="kubectl"
elif [[ -x "$RKE2_DATA_DIR/bin/kubectl" ]]; then
  KUBECTL="$RKE2_DATA_DIR/bin/kubectl"
elif [[ -x /var/lib/rancher/rke2/bin/kubectl ]]; then
  KUBECTL="/var/lib/rancher/rke2/bin/kubectl"
fi

# Applica kubeconfig
if [[ -n "$KUBECONFIG_PATH" ]]; then
  if [[ ! -f "$KUBECONFIG_PATH" ]]; then
    err "Kubeconfig non trovato: $KUBECONFIG_PATH"
    exit 1
  fi
  export KUBECONFIG="$KUBECONFIG_PATH"
  ok "Kubeconfig: $KUBECONFIG_PATH"
elif [[ -z "${KUBECONFIG:-}" ]]; then
  # Auto-detect kubeconfig
  for KC in /etc/rancher/rke2/rke2.yaml "$HOME/.kube/config" "$RKE2_DATA_DIR/server/cred/admin.kubeconfig"; do
    if [[ -f "$KC" ]]; then
      export KUBECONFIG="$KC"
      break
    fi
  done
  if [[ -n "${KUBECONFIG:-}" ]]; then
    info "Kubeconfig auto-rilevato: $KUBECONFIG"
  else
    info "Kubeconfig: default (~/.kube/config)"
  fi
else
  info "Kubeconfig da env: $KUBECONFIG"
fi

# Verifica accesso al cluster
CLUSTER_ACCESS=false
if [[ -n "$KUBECTL" ]] && $KUBECTL cluster-info &>/dev/null; then
  CLUSTER_ACCESS=true
  ok "Accesso al cluster Kubernetes: attivo"
  info "Kubeconfig: ${KUBECONFIG:-default}"
  info "Server: $($KUBECTL cluster-info 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g')"
else
  warn "Accesso al cluster Kubernetes non disponibile"
  warn "Le operazioni ingress non saranno possibili"
fi

# Verifica se siamo su un nodo server RKE2
IS_SERVER_NODE=false
RKE2_TLS_DIR="$RKE2_DATA_DIR/server/tls"

if [[ -d "$RKE2_TLS_DIR" ]]; then
  IS_SERVER_NODE=true
  ok "Nodo server RKE2 rilevato: $RKE2_TLS_DIR"
else
  warn "Directory TLS RKE2 non trovata: $RKE2_TLS_DIR"
  warn "Le operazioni control plane non saranno possibili da questo host"
fi

# Verifica servizio RKE2
RKE2_SERVICE=""
if systemctl list-units --type=service 2>/dev/null | grep -q rke2-server; then
  RKE2_SERVICE="rke2-server"
  ok "Servizio rilevato: rke2-server"
elif systemctl list-units --type=service 2>/dev/null | grep -q rke2-agent; then
  RKE2_SERVICE="rke2-agent"
  info "Servizio rilevato: rke2-agent (nodo agent, no control plane)"
else
  warn "Servizio RKE2 non rilevato tramite systemd"
fi

###############################################################################
# STEP 1: Verifica certificati control plane
###############################################################################
step 1 "Verifica certificati control plane"

EXPIRED_CERTS=()
EXPIRING_CERTS=()

if [[ "$IS_SERVER_NODE" == true ]]; then
  # Certificati principali del control plane RKE2
  declare -A CP_CERTS=(
    ["kube-apiserver"]="$RKE2_TLS_DIR/serving-kube-apiserver.crt"
    ["kube-apiserver-client-kubelet"]="$RKE2_TLS_DIR/client-kube-apiserver.crt"
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
    warn "Certificati in scadenza (<${WARN_DAYS}gg): ${EXPIRING_CERTS[*]}"
  fi
  if [[ ${#EXPIRED_CERTS[@]} -eq 0 && ${#EXPIRING_CERTS[@]} -eq 0 ]]; then
    ok "Tutti i certificati del control plane sono validi"
  fi
else
  info "Skipping — non siamo su un nodo server RKE2"
fi

###############################################################################
# STEP 2: Verifica certificati ingress
###############################################################################
step 2 "Verifica certificati ingress"

INGRESS_EXPIRED=false

if [[ "$CLUSTER_ACCESS" == true ]]; then
  # Rileva ingress controller (nginx o traefik)
  INGRESS_TYPE="unknown"
  if $KUBECTL get deployment -n kube-system rke2-ingress-nginx-controller &>/dev/null; then
    INGRESS_TYPE="nginx"
    INGRESS_NS="kube-system"
    ok "Ingress controller: NGINX (kube-system)"
  elif $KUBECTL get deployment -n ingress-nginx ingress-nginx-controller &>/dev/null; then
    INGRESS_TYPE="nginx"
    INGRESS_NS="ingress-nginx"
    ok "Ingress controller: NGINX (ingress-nginx)"
  elif $KUBECTL get deployment -n kube-system traefik &>/dev/null; then
    INGRESS_TYPE="traefik"
    INGRESS_NS="kube-system"
    ok "Ingress controller: Traefik (kube-system)"
  else
    warn "Ingress controller non rilevato automaticamente"
  fi

  # Cerca secret TLS nelle namespace comuni
  info "Ricerca secret TLS nell'ingress..."
  TLS_SECRETS=$($KUBECTL get secrets -A -o json 2>/dev/null | \
    jq -r '.items[] | select(.type=="kubernetes.io/tls") |
    "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")

  if [[ -n "$TLS_SECRETS" ]]; then
    while IFS='/' read -r NS SECRET; do
      set +e
      check_cert_secret "$NS" "$SECRET" "ingress:$NS/$SECRET" "$KUBECTL"
      RET=$?
      set -e
      if [[ $RET -eq 2 ]]; then
        INGRESS_EXPIRED=true
      fi
    done <<< "$TLS_SECRETS"
  else
    info "Nessun secret TLS trovato nel cluster"
  fi

  # Controlla il default certificate dell'ingress nginx
  if [[ "$INGRESS_TYPE" == "nginx" ]]; then
    DEFAULT_CERT_ARG=$($KUBECTL get deployment -n "$INGRESS_NS" rke2-ingress-nginx-controller \
      -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null | \
      grep -oP 'default-ssl-certificate=\K[^"]+' || echo "")
    if [[ -n "$DEFAULT_CERT_ARG" ]]; then
      IFS='/' read -r DEF_NS DEF_SECRET <<< "$DEFAULT_CERT_ARG"
      info "Default SSL certificate: $DEF_NS/$DEF_SECRET"
      set +e
      check_cert_secret "$DEF_NS" "$DEF_SECRET" "nginx-default-cert" "$KUBECTL"
      set -e
    fi
  fi
else
  info "Skipping — accesso al cluster non disponibile"
fi

###############################################################################
# Se check-only, termina qui
###############################################################################
if [[ "$CHECK_ONLY" == true ]]; then
  divider
  info "Modalità check-only — nessuna modifica applicata"
  divider

  SUMMARY_STATUS="${GREEN}SANI${NC}"
  if [[ ${#EXPIRED_CERTS[@]} -gt 0 || "$INGRESS_EXPIRED" == true ]]; then
    SUMMARY_STATUS="${RED}CERTIFICATI SCADUTI RILEVATI${NC}"
  elif [[ ${#EXPIRING_CERTS[@]} -gt 0 ]]; then
    SUMMARY_STATUS="${YELLOW}CERTIFICATI IN SCADENZA${NC}"
  fi

  echo -e "\nRiepilogo: $SUMMARY_STATUS"
  echo ""
  echo "Per applicare i fix, riesegui con:"
  echo "  $0 --fix-controlplane    # fix control plane"
  echo "  $0 --fix-ingress         # fix ingress"
  echo "  $0 --fix-all             # fix tutto"
  exit 0
fi

# Se nessuna azione specificata, mostra help
if [[ "$FIX_CONTROLPLANE" == false && "$FIX_INGRESS" == false ]]; then
  warn "Nessuna azione di fix specificata."
  echo ""
  echo "Uso:"
  echo "  $0 --check-only          # solo verifica"
  echo "  $0 --fix-controlplane    # rigenera certificati control plane"
  echo "  $0 --fix-ingress --ingress-domain=*.apps.example.com"
  echo "  $0 --fix-all             # fix tutto"
  exit 0
fi

###############################################################################
# STEP 3: Backup certificati esistenti
###############################################################################
step 3 "Backup certificati"

BACKUP_DIR="/root/rke2-certs-backup-$(date +%Y%m%d-%H%M%S)"

if [[ "$FIX_CONTROLPLANE" == true && "$IS_SERVER_NODE" == true ]]; then
  info "Backup certificati control plane in $BACKUP_DIR..."
  mkdir -p "$BACKUP_DIR/tls"

  if cp -a "$RKE2_TLS_DIR/" "$BACKUP_DIR/tls/" 2>/dev/null; then
    ok "Backup completato: $BACKUP_DIR/tls/"
  else
    warn "Backup parziale — alcuni file non copiati (verifica permessi)"
  fi

  # Backup kubeconfig
  for KC in /etc/rancher/rke2/rke2.yaml; do
    if [[ -f "$KC" ]]; then
      cp "$KC" "$BACKUP_DIR/" 2>/dev/null || true
    fi
  done
  ok "Backup kubeconfig completato"
fi

if [[ "$FIX_INGRESS" == true && "$CLUSTER_ACCESS" == true ]]; then
  mkdir -p "$BACKUP_DIR/ingress-secrets"
  info "Backup secret TLS ingress..."

  if [[ -n "$TLS_SECRETS" ]]; then
    while IFS='/' read -r NS SECRET; do
      $KUBECTL get secret "$SECRET" -n "$NS" -o yaml > "$BACKUP_DIR/ingress-secrets/${NS}_${SECRET}.yaml" 2>/dev/null || true
    done <<< "$TLS_SECRETS"
    ok "Backup secret ingress completato"
  fi
fi

###############################################################################
# STEP 4: Fix certificati control plane
###############################################################################
if [[ "$FIX_CONTROLPLANE" == true ]]; then
  step 4 "Rigenerazione certificati control plane"

  if [[ "$IS_SERVER_NODE" == false ]]; then
    err "Impossibile rigenerare i certificati del control plane: non siamo su un nodo server RKE2"
    err "Esegui questo script direttamente su un nodo server (master)"
    exit 1
  fi

  if [[ -z "$RKE2_SERVICE" || "$RKE2_SERVICE" != "rke2-server" ]]; then
    err "Servizio rke2-server non trovato su questo nodo"
    exit 1
  fi

  # Metodo 1: certificate rotation con flag (RKE2 >= 1.28)
  info "Tentativo di rotazione certificati tramite RKE2..."

  # Elimina i certificati scaduti per forzare la rigenerazione
  if [[ ${#EXPIRED_CERTS[@]} -gt 0 ]]; then
    info "Rimozione certificati scaduti per forzare la rigenerazione..."

    for CERT_NAME in "${EXPIRED_CERTS[@]}"; do
      CERT_PATH="${CP_CERTS[$CERT_NAME]:-}"
      KEY_PATH="${CERT_PATH%.crt}.key"

      if [[ -n "$CERT_PATH" && -f "$CERT_PATH" ]]; then
        info "Rimuovo: $CERT_PATH"
        rm -f "$CERT_PATH"
        [[ -f "$KEY_PATH" ]] && rm -f "$KEY_PATH"
      fi
    done
    ok "Certificati scaduti rimossi"
  else
    info "Nessun certificato scaduto da rimuovere, forzo la rigenerazione di tutti..."

    # Rimuovi tutti i certificati non-CA per forzare la rigenerazione
    for CERT_NAME in "${!CP_CERTS[@]}"; do
      CERT_PATH="${CP_CERTS[$CERT_NAME]}"
      # Non rimuovere i CA certificates
      if [[ "$CERT_NAME" == *"-ca"* ]]; then
        info "Mantengo CA: $CERT_NAME"
        continue
      fi
      if [[ -f "$CERT_PATH" ]]; then
        info "Rimuovo: $CERT_NAME ($CERT_PATH)"
        rm -f "$CERT_PATH"
        KEY_PATH="${CERT_PATH%.crt}.key"
        [[ -f "$KEY_PATH" ]] && rm -f "$KEY_PATH"
      fi
    done
    ok "Certificati non-CA rimossi"
  fi

  # Riavvia RKE2 per rigenerare i certificati
  info "Riavvio servizio rke2-server per rigenerare i certificati..."
  warn "ATTENZIONE: il cluster sarà temporaneamente non disponibile"

  systemctl restart rke2-server

  info "Attendo il riavvio di rke2-server (max 180s)..."
  for i in $(seq 1 60); do
    if systemctl is-active rke2-server &>/dev/null; then
      # Verifica che l'apiserver risponda
      if $KUBECTL get nodes &>/dev/null 2>&1; then
        ok "rke2-server attivo e apiserver raggiungibile"
        break
      fi
    fi
    echo -n "."
    sleep 3
  done
  echo ""

  if ! systemctl is-active rke2-server &>/dev/null; then
    err "rke2-server non si è riavviato correttamente"
    err "Controlla i log con: journalctl -u rke2-server -f"
    err "Backup disponibile in: $BACKUP_DIR"
    exit 1
  fi

  # Verifica nuovi certificati
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
    ok "Tutti i certificati del control plane sono stati rigenerati con successo"
  else
    err "$NEW_EXPIRED certificati ancora scaduti — controlla i log di rke2-server"
  fi
fi

###############################################################################
# STEP 5: Fix certificati ingress
###############################################################################
if [[ "$FIX_INGRESS" == true ]]; then
  STEP_NUM=5
  [[ "$FIX_CONTROLPLANE" == false ]] && STEP_NUM=4
  step $STEP_NUM "Rigenerazione certificato ingress"

  if [[ "$CLUSTER_ACCESS" == false ]]; then
    err "Impossibile operare sull'ingress: accesso al cluster non disponibile"
    exit 1
  fi

  # Rileva dominio se non specificato
  if [[ -z "$INGRESS_DOMAIN" ]]; then
    info "Rilevamento automatico dominio ingress..."

    # Prova dalle ingress resources
    DETECTED_DOMAINS=$($KUBECTL get ingress -A -o json 2>/dev/null | \
      jq -r '.items[].spec.rules[]?.host // empty' 2>/dev/null | \
      sed 's/^[^.]*\.//' | sort -u || echo "")

    if [[ -n "$DETECTED_DOMAINS" ]]; then
      # Prendi il dominio più comune
      INGRESS_DOMAIN=$(echo "$DETECTED_DOMAINS" | head -1)
      info "Dominio rilevato dalle ingress: $INGRESS_DOMAIN"
    fi
  fi

  if [[ -z "$INGRESS_DOMAIN" ]]; then
    err "Dominio ingress non specificato e non rilevabile automaticamente"
    err "Riesegui con: $0 --fix-ingress --ingress-domain=apps.example.com"
    exit 1
  fi

  WILDCARD_CN="*.$INGRESS_DOMAIN"
  ok "Dominio wildcard: $WILDCARD_CN"

  # Genera nuovo certificato self-signed
  TMPDIR=$(mktemp -d)
  info "Generazione certificato self-signed wildcard ($CERT_VALIDITY_DAYS giorni)..."

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$TMPDIR/wildcard.key" \
    -x509 -days "$CERT_VALIDITY_DAYS" \
    -out "$TMPDIR/wildcard.crt" \
    -subj "/CN=$WILDCARD_CN" \
    -addext "subjectAltName=DNS:$WILDCARD_CN,DNS:$INGRESS_DOMAIN" 2>/dev/null

  ok "Certificato generato"
  openssl x509 -in "$TMPDIR/wildcard.crt" -noout -dates -subject

  # Trova e aggiorna i secret TLS scaduti
  UPDATED_SECRETS=0

  if [[ -n "$TLS_SECRETS" ]]; then
    while IFS='/' read -r NS SECRET; do
      # Controlla se questo secret è scaduto
      CERT_DATA=$($KUBECTL get secret "$SECRET" -n "$NS" -o jsonpath='{.data.tls\.crt}' 2>/dev/null || echo "")
      if [[ -z "$CERT_DATA" ]]; then continue; fi

      NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
      EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
      NOW_EPOCH=$(date +%s)

      if (( EXPIRY_EPOCH < NOW_EPOCH )); then
        info "Aggiornamento secret scaduto: $NS/$SECRET"
        $KUBECTL create secret tls "$SECRET" \
          --cert="$TMPDIR/wildcard.crt" \
          --key="$TMPDIR/wildcard.key" \
          -n "$NS" \
          --dry-run=client -o yaml | $KUBECTL replace -f - 2>/dev/null

        if [[ $? -eq 0 ]]; then
          ok "Secret $NS/$SECRET aggiornato"
          ((UPDATED_SECRETS++))
        else
          warn "Impossibile aggiornare $NS/$SECRET"
        fi
      fi
    done <<< "$TLS_SECRETS"
  fi

  # Se nessun secret aggiornato, crea/aggiorna il default
  if [[ $UPDATED_SECRETS -eq 0 ]]; then
    info "Nessun secret scaduto trovato — creo/aggiorno il default TLS secret"

    DEFAULT_SECRET_NS="${INGRESS_NS:-kube-system}"
    DEFAULT_SECRET_NAME="default-tls-cert"

    $KUBECTL create secret tls "$DEFAULT_SECRET_NAME" \
      --cert="$TMPDIR/wildcard.crt" \
      --key="$TMPDIR/wildcard.key" \
      -n "$DEFAULT_SECRET_NS" \
      --dry-run=client -o yaml | $KUBECTL apply -f -

    ok "Secret $DEFAULT_SECRET_NS/$DEFAULT_SECRET_NAME creato/aggiornato"
  fi

  # Riavvia l'ingress controller
  info "Riavvio ingress controller..."
  if [[ "$INGRESS_TYPE" == "nginx" ]]; then
    $KUBECTL rollout restart deployment/rke2-ingress-nginx-controller -n "$INGRESS_NS" 2>/dev/null || \
    $KUBECTL rollout restart deployment/ingress-nginx-controller -n "$INGRESS_NS" 2>/dev/null || \
    $KUBECTL delete pods -n "$INGRESS_NS" -l app.kubernetes.io/component=controller 2>/dev/null || true
  elif [[ "$INGRESS_TYPE" == "traefik" ]]; then
    $KUBECTL rollout restart deployment/traefik -n "$INGRESS_NS" 2>/dev/null || true
  else
    warn "Ingress controller sconosciuto — riavvia manualmente i pod dell'ingress"
  fi
  ok "Ingress controller riavviato"

  rm -rf "$TMPDIR"
fi

###############################################################################
# STEP FINALE: Verifica complessiva
###############################################################################
FINAL_STEP=6
[[ "$FIX_CONTROLPLANE" == false || "$FIX_INGRESS" == false ]] && FINAL_STEP=5
step $FINAL_STEP "Verifica finale"

divider

# Verifica nodi
if [[ "$CLUSTER_ACCESS" == true ]]; then
  info "Stato nodi:"
  $KUBECTL get nodes -o wide 2>/dev/null || warn "Impossibile ottenere lo stato dei nodi"
  echo ""
fi

# Verifica control plane pods
if [[ "$CLUSTER_ACCESS" == true ]]; then
  info "Stato pod control plane:"
  $KUBECTL get pods -n kube-system -o wide 2>/dev/null | \
    grep -E "kube-apiserver|kube-controller|kube-scheduler|etcd" || \
    info "Pod control plane gestiti come static pods"
  echo ""
fi

# Verifica servizio RKE2
if [[ -n "$RKE2_SERVICE" ]]; then
  info "Stato servizio RKE2:"
  systemctl is-active "$RKE2_SERVICE" 2>/dev/null && ok "$RKE2_SERVICE è attivo" || warn "$RKE2_SERVICE non attivo"
fi

# Riepilogo
divider
OVERALL_OK=true

if [[ "$FIX_CONTROLPLANE" == true && "$IS_SERVER_NODE" == true ]]; then
  CP_EXPIRED=0
  for CERT_NAME in $(echo "${!CP_CERTS[@]}" | tr ' ' '\n' | sort); do
    CERT_PATH="${CP_CERTS[$CERT_NAME]}"
    NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
    EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    (( EXPIRY_EPOCH < NOW_EPOCH )) && ((CP_EXPIRED++))
  done

  if [[ $CP_EXPIRED -eq 0 ]]; then
    ok "Control plane: tutti i certificati validi ✅"
  else
    err "Control plane: $CP_EXPIRED certificati ancora scaduti ❌"
    OVERALL_OK=false
  fi
fi

if [[ "$FIX_INGRESS" == true && "$CLUSTER_ACCESS" == true ]]; then
  info "Ingress: $UPDATED_SECRETS secret aggiornati"
fi

divider
if [[ "$OVERALL_OK" == true ]]; then
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  ✅ OPERAZIONE COMPLETATA CON SUCCESSO!          ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
else
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║  ⚠️  Operazione completata con avvertimenti.                 ║${NC}"
  echo -e "${YELLOW}║  Controlla i log: journalctl -u rke2-server -f              ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
fi

if [[ -d "$BACKUP_DIR" ]]; then
  info "Backup disponibile in: $BACKUP_DIR"
fi

info "Script completato — $(date)"
