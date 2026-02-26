#!/bin/bash
###############################################################################
# fix-ocp-router-certs.sh
# Script per rigenerare il certificato wildcard del router OpenShift
# e propagarlo a tutti i componenti che lo utilizzano.
#
# Uso: ./fix-ocp-router-certs.sh [OPZIONI]
#
#   --kubeconfig=PATH   Path al kubeconfig (supporto multi-ambiente)
#   --force-selfsigned  Salta l'attesa della rigenerazione automatica e
#                       genera subito un certificato self-signed
#   --fix-imagepull     Applica il patch IfNotPresent ai deployment operator
#                       in caso di cluster air-gapped / senza accesso a quay.io
###############################################################################

set -euo pipefail

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FORCE_SELFSIGNED=false
FIX_IMAGEPULL=false
KUBECONFIG_PATH=""

# Help rapido (prima del check dipendenze)
for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    echo "Uso: $0 [OPZIONI]"
    echo ""
    echo "Opzioni:"
    echo "  --kubeconfig=PATH   Path al kubeconfig (supporto multi-ambiente)"
    echo "  --force-selfsigned  Genera subito un certificato self-signed senza attendere l'operator"
    echo "  --fix-imagepull     Patch imagePullPolicy=IfNotPresent sugli operator (cluster air-gapped)"
    echo ""
    echo "Esempi:"
    echo "  $0 --kubeconfig=/path/to/ocp-prod.kubeconfig"
    echo "  $0 --kubeconfig=/path/to/ocp-dev.kubeconfig --force-selfsigned"
    echo "  $0 --kubeconfig=/path/to/ocp-airgapped.kubeconfig --fix-imagepull"
    exit 0
  fi
done

###############################################################################
# Verifica dipendenze
###############################################################################
REQUIRED_TOOLS=(oc openssl jq base64 date sed grep wc tr mktemp)
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    MISSING_TOOLS+=("$tool")
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo -e "${RED}[ERRORE]${NC} Tool mancanti: ${MISSING_TOOLS[*]}"
  echo -e "${RED}[ERRORE]${NC} Installa i tool mancanti prima di eseguire lo script."
  echo ""
  echo "  Esempio (RHEL/CentOS/Fedora):"
  echo "    sudo dnf install -y jq openssl coreutils"
  echo ""
  echo "  Esempio (Debian/Ubuntu):"
  echo "    sudo apt install -y jq openssl coreutils"
  exit 1
fi

echo -e "${GREEN}[OK]${NC}    Tutti i tool richiesti sono presenti: ${REQUIRED_TOOLS[*]}"

###############################################################################
# Parsing argomenti
###############################################################################
while [[ $# -gt 0 ]]; do
  case $1 in
    --force-selfsigned)   FORCE_SELFSIGNED=true; shift ;;
    --fix-imagepull)      FIX_IMAGEPULL=true; shift ;;
    --kubeconfig=*)       KUBECONFIG_PATH="${1#*=}"; shift ;;
    --kubeconfig)         KUBECONFIG_PATH="${2:-}"; shift 2 ;;
    -h|--help)            exit 0 ;;
    *) echo "Opzione sconosciuta: $1"; exit 1 ;;
  esac
done

###############################################################################
# Applica kubeconfig
###############################################################################
if [[ -n "$KUBECONFIG_PATH" ]]; then
  if [[ ! -f "$KUBECONFIG_PATH" ]]; then
    echo -e "${RED}[ERRORE]${NC} Kubeconfig non trovato: $KUBECONFIG_PATH"
    exit 1
  fi
  export KUBECONFIG="$KUBECONFIG_PATH"
  echo -e "${GREEN}[OK]${NC}    Kubeconfig: $KUBECONFIG_PATH"
elif [[ -n "${KUBECONFIG:-}" ]]; then
  echo -e "${CYAN}[INFO]${NC}  Kubeconfig da env: $KUBECONFIG"
else
  echo -e "${CYAN}[INFO]${NC}  Kubeconfig: default (~/.kube/config)"
fi

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERRORE]${NC} $*"; }
step()    { echo -e "\n${GREEN}━━━ STEP $1 ━━━${NC} $2"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────────${NC}"; }

###############################################################################
# Pre-flight checks
###############################################################################
divider
info "Avvio fix-ocp-router-certs.sh - $(date)"
divider

if ! command -v oc &>/dev/null; then
  err "Comando 'oc' non trovato. Assicurati di avere oc nel PATH."
  exit 1
fi

if ! oc whoami &>/dev/null; then
  err "Non sei autenticato al cluster. Esegui 'oc login' prima."
  exit 1
fi

CLUSTER_USER=$(oc whoami)
CLUSTER_API=$(oc whoami --show-server)
info "Utente:  $CLUSTER_USER"
info "Cluster: $CLUSTER_API"

###############################################################################
# Rileva il dominio wildcard delle apps
###############################################################################
step 1 "Rilevamento dominio wildcard apps"

APPS_DOMAIN=$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}' 2>/dev/null || true)

if [[ -z "$APPS_DOMAIN" ]]; then
  # Fallback: prova dalla route console
  APPS_DOMAIN=$(oc get route console -n openshift-console -o jsonpath='{.spec.host}' 2>/dev/null | sed 's/^console-openshift-console\.//')
fi

if [[ -z "$APPS_DOMAIN" ]]; then
  err "Impossibile determinare il dominio apps del cluster."
  exit 1
fi

ok "Dominio apps: $APPS_DOMAIN"
WILDCARD_CN="*.$APPS_DOMAIN"
info "Wildcard CN: $WILDCARD_CN"

###############################################################################
# Controlla lo stato attuale del certificato
###############################################################################
step 2 "Verifica certificato attuale del router"

CERT_DATA=$(oc get secret router-certs-default -n openshift-ingress \
  -o jsonpath='{.data.tls\.crt}' 2>/dev/null || true)

if [[ -n "$CERT_DATA" ]]; then
  CERT_DATES=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -dates -subject 2>/dev/null || true)
  if [[ -n "$CERT_DATES" ]]; then
    echo "$CERT_DATES"
    NOT_AFTER=$(echo "$CERT_DATA" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$NOT_AFTER" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)

    if (( EXPIRY_EPOCH > NOW_EPOCH )); then
      ok "Il certificato è ancora valido (scade: $NOT_AFTER)"
      echo ""
      read -rp "Vuoi continuare comunque con la rigenerazione? (s/N) " REPLY
      if [[ ! "$REPLY" =~ ^[sSyY]$ ]]; then
        info "Operazione annullata."
        exit 0
      fi
    else
      warn "Certificato SCADUTO il $NOT_AFTER"
    fi
  else
    warn "Impossibile decodificare il certificato attuale"
  fi
else
  warn "Secret router-certs-default non trovato in openshift-ingress"
fi

###############################################################################
# Controlla stato degli operator impattati
###############################################################################
step 3 "Stato attuale degli operator impattati"

for OP in authentication console ingress; do
  STATUS=$(oc get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null || echo "Unknown")
  DEGRADED=$(oc get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].status}' 2>/dev/null || echo "Unknown")
  if [[ "$DEGRADED" == "True" ]]; then
    warn "$OP: Available=$STATUS, Degraded=$DEGRADED"
  else
    ok "$OP: Available=$STATUS, Degraded=$DEGRADED"
  fi
done

###############################################################################
# Elimina il secret del router
###############################################################################
step 4 "Eliminazione secret router-certs-default"

if oc get secret router-certs-default -n openshift-ingress &>/dev/null; then
  oc delete secret router-certs-default -n openshift-ingress
  ok "Secret eliminato da openshift-ingress"
else
  info "Secret già assente in openshift-ingress"
fi

###############################################################################
# Riavvia l'ingress-operator per triggerare la rigenerazione
###############################################################################
step 5 "Riavvio ingress-operator"

oc delete pods --all -n openshift-ingress-operator 2>/dev/null || true
info "Pod dell'ingress-operator eliminati, attendo il restart..."
sleep 5

# Attendi che il pod dell'operator torni Running
for i in $(seq 1 30); do
  PHASE=$(oc get pods -n openshift-ingress-operator -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "Pending")
  if [[ "$PHASE" == "Running" ]]; then
    ok "Ingress-operator Running"
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

###############################################################################
# Attendi la rigenerazione automatica del secret (o genera self-signed)
###############################################################################
step 6 "Attesa rigenerazione certificato"

CERT_REGENERATED=false

if [[ "$FORCE_SELFSIGNED" == false ]]; then
  info "Attendo che l'ingress-operator rigeneri il secret (max 60s)..."
  for i in $(seq 1 12); do
    if oc get secret router-certs-default -n openshift-ingress &>/dev/null; then
      NEW_DATES=$(oc get secret router-certs-default -n openshift-ingress \
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
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$TMPDIR/wildcard.key" \
    -x509 -days 730 \
    -out "$TMPDIR/wildcard.crt" \
    -subj "/CN=$WILDCARD_CN" \
    -addext "subjectAltName=DNS:$WILDCARD_CN" 2>/dev/null

  oc create secret tls router-certs-default \
    --cert="$TMPDIR/wildcard.crt" \
    --key="$TMPDIR/wildcard.key" \
    -n openshift-ingress

  NEW_DATES=$(oc get secret router-certs-default -n openshift-ingress \
    -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates 2>/dev/null)
  ok "Certificato self-signed creato"
  echo "$NEW_DATES"

  rm -rf "$TMPDIR"
fi

###############################################################################
# Riavvia i router pods
###############################################################################
step 7 "Riavvio router pods"

oc rollout restart deployment/router-default -n openshift-ingress 2>/dev/null || \
  oc delete pods --all -n openshift-ingress 2>/dev/null || true
info "Attendo che i router siano pronti..."
oc rollout status deployment/router-default -n openshift-ingress --timeout=120s 2>/dev/null || \
  warn "Timeout rollout router — potrebbe richiedere più tempo"
ok "Router riavviati"

###############################################################################
# Propaga il certificato a openshift-config-managed
###############################################################################
step 8 "Propagazione certificato a openshift-config-managed"

# Elimina il vecchio se presente
oc delete secret router-certs-default -n openshift-config-managed 2>/dev/null || true

# Copia il nuovo
oc get secret router-certs-default -n openshift-ingress -o json | \
  jq '.metadata.namespace = "openshift-config-managed" |
      del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp, .metadata.managedFields)' | \
  oc apply -f -

ok "Secret copiato in openshift-config-managed"

###############################################################################
# Pulisci il secret cached in openshift-authentication
###############################################################################
step 9 "Pulizia secret cached in openshift-authentication"

if oc get secret v4-0-config-system-router-certs -n openshift-authentication &>/dev/null; then
  oc delete secret v4-0-config-system-router-certs -n openshift-authentication
  ok "Secret v4-0-config-system-router-certs eliminato"
else
  info "Secret v4-0-config-system-router-certs non presente (verrà ricreato)"
fi

###############################################################################
# Riavvia authentication-operator e pod oauth
###############################################################################
step 10 "Riavvio authentication-operator e pod oauth"

# Fix per cluster air-gapped
if [[ "$FIX_IMAGEPULL" == true ]]; then
  info "Applico patch imagePullPolicy=IfNotPresent su authentication-operator..."
  oc patch deployment authentication-operator -n openshift-authentication-operator \
    --type=json \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' 2>/dev/null || true
fi

oc delete pods --all -n openshift-authentication-operator 2>/dev/null || true
info "Attendo che l'authentication-operator sia Running..."

for i in $(seq 1 60); do
  READY=$(oc get pods -n openshift-authentication-operator -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null || echo "false")
  if [[ "$READY" == "true" ]]; then
    ok "Authentication-operator Running"
    break
  fi
  # Detect ImagePullBackOff
  POD_STATUS=$(oc get pods -n openshift-authentication-operator -o jsonpath='{.items[0].status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || echo "")
  if [[ "$POD_STATUS" == "ImagePullBackOff" || "$POD_STATUS" == "ErrImagePull" ]]; then
    warn "ImagePullBackOff rilevato — applico patch IfNotPresent"
    oc patch deployment authentication-operator -n openshift-authentication-operator \
      --type=json \
      -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' 2>/dev/null || true
  fi
  echo -n "."
  sleep 3
done
echo ""

info "Riavvio pod oauth..."
oc delete pods --all -n openshift-authentication 2>/dev/null || true

info "Attendo che i pod oauth siano pronti (max 120s)..."
for i in $(seq 1 40); do
  RUNNING=$(oc get pods -n openshift-authentication --no-headers 2>/dev/null | grep -c "Running" || echo 0)
  TOTAL=$(oc get pods -n openshift-authentication --no-headers 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$RUNNING" -gt 0 && "$RUNNING" -eq "$TOTAL" ]]; then
    ok "Pod oauth Running ($RUNNING/$TOTAL)"
    break
  fi
  echo -n "."
  sleep 3
done
echo ""

###############################################################################
# Verifica finale
###############################################################################
step 11 "Verifica finale"

info "Attendo 60 secondi per la riconciliazione degli operator..."
sleep 60

divider
info "Stato ClusterOperators:"
divider

ALL_OK=true
for OP in authentication console ingress; do
  AVAILABLE=$(oc get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null || echo "Unknown")
  DEGRADED=$(oc get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].status}' 2>/dev/null || echo "Unknown")
  MSG=$(oc get co "$OP" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].message}' 2>/dev/null || echo "")

  if [[ "$AVAILABLE" == "True" && "$DEGRADED" == "False" ]]; then
    ok "$OP: Available=$AVAILABLE, Degraded=$DEGRADED ✅"
  else
    warn "$OP: Available=$AVAILABLE, Degraded=$DEGRADED"
    [[ -n "$MSG" ]] && echo "     Messaggio: ${MSG:0:200}"
    ALL_OK=false
  fi
done

divider
info "Certificato attuale servito dal router:"
OAUTH_HOST=$(oc get route oauth-openshift -n openshift-authentication -o jsonpath='{.spec.host}' 2>/dev/null || echo "oauth-openshift.$APPS_DOMAIN")
echo | openssl s_client -connect "$OAUTH_HOST":443 -servername "$OAUTH_HOST" 2>/dev/null | \
  openssl x509 -noout -dates -subject 2>/dev/null || warn "Impossibile verificare il certificato via TLS"

divider
if [[ "$ALL_OK" == true ]]; then
  echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  ✅ TUTTI GLI OPERATOR SONO TORNATI SANI!   ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
else
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║  ⚠️  Alcuni operator non sono ancora completamente sani.    ║${NC}"
  echo -e "${YELLOW}║  Attendi qualche minuto e verifica con: oc get co           ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
fi

info "Script completato — $(date)"
