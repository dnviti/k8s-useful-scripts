#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# pvc-storageclass-migrate.sh
#
# Generic PVC StorageClass migration with offline data copy and PV rebind.
# Works with both `oc` (OpenShift) and plain `kubectl`. The script
# auto-detects which client is in PATH (preferring `oc`) or you can force
# one with --kube-bin. OpenShift-only checks (ClusterOperators,
# MachineConfigPools) are skipped when those APIs are not present, so the
# script runs cleanly on any conformant Kubernetes cluster.
#
# Migrates every Bound PVC currently on a source StorageClass over to a
# target StorageClass. The PVC name, labels, annotations, accessModes, size
# and volumeMode are preserved. The original PV is left as a rollback
# artifact in Released + Retain, labelled storage-migration=backup.
#
# Per PVC, the script does, one at a time:
#   1.  Patch the source PV to reclaimPolicy=Retain, add a custom protection
#       finalizer, label it storage-migration=backup, annotate with the
#       original claim and a timestamp. The patched source PV is the
#       rollback artifact.
#   2.  Create a backup PVC on the source StorageClass with the same size,
#       accessModes and volumeMode, copy the original PVC data into it, verify
#       file count and byte count, then retain and finalizer-protect its PV.
#   3.  Create a temporary target PVC on the target StorageClass with the
#       same size, accessModes and volumeMode.
#   4.  Run a privileged restore pod that mounts /src (backup claim) and /dst
#       (temp target claim) and restores the data with:
#         tar --xattrs --acls --selinux --numeric-owner -cpf - -C /src .
#           | tar --xattrs --acls --selinux --numeric-owner -xpf - -C /dst
#       It then verifies that source and destination report the same stable
#       manifest hash, entry count and regular-file byte total.
#   5.  Patch the target PV to reclaimPolicy=Retain and add the protection
#       finalizer so the freshly written volume cannot be deleted accidentally
#       during the rebind window.
#   6.  Delete the original PVC, wait for the source PV to go Released.
#   7.  Delete the temp PVC, wait for the target PV to go Released, strip
#       its claimRef.
#   8.  Recreate the original PVC name pointing at the target PV (preserves
#       labels and annotations), waits Bound, then resets the target PV
#       reclaimPolicy back to Delete and removes the protection finalizer.
#
# Around the per-PVC primitive, per impacted namespace:
#   - discover top-level controllers using the candidate claims (Deployment,
#     StatefulSet, DeploymentConfig, ReplicaSet, ReplicationController),
#     save current replica counts to disk
#   - scale them to 0 so no pod can write to the claim during the copy
#   - wait until no pod in the namespace mounts any candidate claim
#   - for every StatefulSet whose volumeClaimTemplates point at a non-target
#     StorageClass, recreate the StatefulSet with --cascade=orphan and the
#     template patched to the target StorageClass (so future PVCs from the
#     StatefulSet land on the target SC even without relying on the default)
#   - run the per-PVC primitive for each candidate
#   - restore replicas to the saved values and wait for them to be ready
#
# Cluster-wide, before any per-namespace work:
#   - flip the default StorageClass annotation so newly created PVCs land on
#     the target SC: target=true, every other SC=false (skip with
#     --no-set-default)
#   - run a 1 GiB smoke test on the target SC (PVC + pod, then cleanup)
#
# After everything:
#   - verify every candidate PVC is now Bound on the target SC
#   - verify pods in impacted namespaces are Running (or were before)
#   - verify every ClusterOperator (if present) is Available, not Progressing,
#     not Degraded
#   - remove the protection finalizer from each retained source PV unless
#     --keep-finalizers is set. Data-backup PVCs/PVs are kept by default.
#
# Modes:
#   --dry-run  (default) read the cluster only. No apply/create/delete/
#              scale/patch/annotate is executed. Every mutating call site is
#              guarded by an is_dry_run check and only logs what it would do.
#   --execute  perform the work. Requires CONFIRM=yes in the environment
#              OR the --yes flag on the CLI.
#
# Required input:
#   --source-sc NAME       source StorageClass (or env SOURCE_SC)
#   --source-sc-regex RE   source StorageClass regex (or env SOURCE_SC_REGEX)
#   --target-sc NAME       target StorageClass (or --destination-sc, env TARGET_SC)
#
# Optional input:
#   -c, --config PATH      YAML config file. CLI flags override config values.
#   --kubeconfig PATH      kubeconfig file. If unset, the chosen client uses
#                          its own default discovery ($KUBECONFIG env, then
#                          ~/.kube/config).
#   --data-backup-sc NAME  StorageClass for backup PVCs. Defaults to each
#                          PVC's current source StorageClass.
#
# Rollback: see ROLLBACK section at the bottom of this header for the
# per-PVC reversal procedure that uses the storage-migration=backup PVs.
# =============================================================================


# -----------------------------------------------------------------------------
# Defaults (all overridable via CLI and / or environment)
# -----------------------------------------------------------------------------

KUBE_BIN="${KUBE_BIN:-}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-}"
SOURCE_SC="${SOURCE_SC:-}"
SOURCE_SC_REGEX="${SOURCE_SC_REGEX:-}"
TARGET_SC="${TARGET_SC:-}"
INCLUDE_NS_REGEX="${INCLUDE_NS_REGEX:-.*}"
EXCLUDE_NS_REGEX="${EXCLUDE_NS_REGEX:-^$}"
INCLUDE_CLAIM_REGEX="${INCLUDE_CLAIM_REGEX:-.*}"
EXCLUDE_CLAIM_REGEX="${EXCLUDE_CLAIM_REGEX:-^$}"
SET_DEFAULT_SC="${SET_DEFAULT_SC:-yes}"
RUN_SMOKE_TEST="${RUN_SMOKE_TEST:-yes}"
COPY_IMAGE="${COPY_IMAGE:-registry.access.redhat.com/ubi9/ubi:latest}"
BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-$PWD/pvc-migration-backups}"
WORKLOAD_STOP_TIMEOUT="${WORKLOAD_STOP_TIMEOUT:-1800}"
WORKLOAD_READY_TIMEOUT="${WORKLOAD_READY_TIMEOUT:-1800}"
COPY_TIMEOUT="${COPY_TIMEOUT:-14400}"
STEP_PAUSES="${STEP_PAUSES:-yes}"
ALLOW_DEGRADED="${ALLOW_DEGRADED:-no}"
ALSO_SCALE="${ALSO_SCALE:-}"
DATA_BACKUP_SC="${DATA_BACKUP_SC:-}"
SKIP_SECRETS_BACKUP="${SKIP_SECRETS_BACKUP:-no}"
SKIP_UNSUPPORTED_CLAIMS="${SKIP_UNSUPPORTED_CLAIMS:-no}"
KEEP_FINALIZERS="${KEEP_FINALIZERS:-no}"
KEEP_DATA_BACKUPS="${KEEP_DATA_BACKUPS:-yes}"
FINALIZER="${FINALIZER:-pvc-migration.local/protect}"
WORKDIR_OVERRIDE="${WORKDIR_OVERRIDE:-}"
CONFIG_FILE="${CONFIG_FILE:-}"

DRY_RUN="yes"
CONFIRM="${CONFIRM:-no}"
YES_FLAG="no"
CLEANUP_FINALIZERS_ONLY="no"

WORKDIR=""
RESULTS_TSV=""
PROTECTED_SOURCE_PVS_FILE=""
DATA_BACKUPS_TSV=""
SMOKE_NS="pvc-migration-smoke"
SMOKE_PVC="target-sc-smoke"
SMOKE_POD="target-sc-smoke"

declare -a CANDIDATE_ROWS=()
declare -a IMPACTED_NAMESPACES=()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*"
}

die() {
  printf '[%s] ERROR: %s\n' "$(date -Is)" "$*" >&2
  exit 1
}

is_dry_run() {
  [[ "${DRY_RUN}" == "yes" ]]
}

dry_log() {
  log "DRY-RUN: $*"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "Required binary not found: $1"
}

detect_kube_binary() {
  if [[ -n "${KUBE_BIN}" ]]; then
    command -v "${KUBE_BIN}" >/dev/null 2>&1 || die "Requested --kube-bin not found in PATH: ${KUBE_BIN}"
    return 0
  fi
  if command -v oc >/dev/null 2>&1; then
    KUBE_BIN="oc"
  elif command -v kubectl >/dev/null 2>&1; then
    KUBE_BIN="kubectl"
  else
    die "Neither oc nor kubectl found in PATH. Install one or pass --kube-bin."
  fi
}

kc() {
  if [[ -n "${KUBECONFIG_PATH}" ]]; then
    "${KUBE_BIN}" --kubeconfig="${KUBECONFIG_PATH}" "$@"
  else
    "${KUBE_BIN}" "$@"
  fi
}

tsv_get() {
  local row="$1" idx="$2"
  awk -F'\t' -v i="${idx}" '{print $i}' <<< "${row}"
}

namespace_slug() {
  sed 's/[^A-Za-z0-9_.-]/_/g' <<< "$1"
}

k8s_temp_name() {
  local prefix="$1" claim="$2" stamp="$3"
  local max_claim_len=$((63 - ${#prefix} - ${#stamp} - 2))
  (( max_claim_len > 0 )) || die "Internal error: temporary name prefix too long: ${prefix}"
  printf '%s-%s-%s' "${prefix}" "${claim:0:max_claim_len}" "${stamp}"
}

join_alt() {
  local IFS='|'
  printf '%s' "$*"
}

usage() {
  cat <<EOF
Usage:
  $0 --source-sc NAME --target-sc NAME [options]
  $0 -c CONFIG.yaml [options]

Required:
  --source-sc NAME       source StorageClass to migrate away from
  --source-sc-regex REGEX
                         source StorageClass regex selector
  --target-sc NAME       target StorageClass to migrate to
                         (alias: --destination-sc)
  -c, --config PATH      YAML config file. CLI flags override config values.

Modes:
  --dry-run              read cluster only, no changes (default)
  --execute              perform the migration (requires CONFIRM=yes or --yes)
  --yes                  equivalent to CONFIRM=yes for starting execute mode;
                         sensitive-operation prompts still apply unless disabled
  --cleanup-finalizers   only remove ${FINALIZER} from PVs
                         labelled storage-migration=backup, then exit
  -h, --help             show this help

Selection:
  --kube-bin BIN         kubernetes CLI to use (oc or kubectl, or a path).
                         If omitted, the script picks oc when present and
                         falls back to kubectl.
  --kubeconfig PATH      kubeconfig file. If omitted, the chosen client uses
                         its own default discovery (\$KUBECONFIG env, then
                         ~/.kube/config).
  --namespace REGEX      namespace include regex (default: ${INCLUDE_NS_REGEX})
  --exclude-ns REGEX     namespace exclude regex (default: ${EXCLUDE_NS_REGEX})
  --claim REGEX          PVC include regex (default: ${INCLUDE_CLAIM_REGEX})
  --exclude-claim REGEX  PVC exclude regex (default: ${EXCLUDE_CLAIM_REGEX})

Behavior:
  --no-set-default       do not flip default StorageClass
  --no-smoke-test        skip the smoke test on the target SC
  --copy-image IMAGE     image for the copy pod
                         (default: ${COPY_IMAGE})
  --backup-dir DIR       parent dir for the run workspace (a timestamped
                         subdir is created inside it)
                         (default: ${BACKUP_BASE_DIR})
  --workdir DIR          exact destination directory for backups + run state
                         (overrides --backup-dir, no timestamp suffix is
                         appended)
  --workload-stop-timeout SEC   default ${WORKLOAD_STOP_TIMEOUT}
  --workload-ready-timeout SEC  default ${WORKLOAD_READY_TIMEOUT}
  --copy-timeout SEC            default ${COPY_TIMEOUT}
  --no-step-pauses       do not pause before sensitive execute operations
                         (not recommended for production)
  --allow-degraded       proceed even if a ClusterOperator is Degraded
  --also-scale LIST      extra workloads to scale to 0 (comma-separated
                         ns/Kind/name)
  --data-backup-sc NAME  StorageClass for backup PVCs. Defaults to each
                         PVC's current source StorageClass.
  --delete-data-backups-after-restore
                         delete backup PVCs after successful restore/rebind
                         (default keeps them)
  --skip-secrets-backup  do not dump Secret manifests during backup
  --skip-unsupported-claims
                         skip unsupported candidate PVCs instead of stopping
  --keep-finalizers      do not remove ${FINALIZER}
                         from source PVs at the end of the run
  --finalizer NAME       protection finalizer (default: ${FINALIZER})

Environment overrides (same as CLI flags):
  CONFIRM=yes            required for --execute
  KUBE_BIN, KUBECONFIG_PATH, SOURCE_SC, TARGET_SC, INCLUDE_NS_REGEX, EXCLUDE_NS_REGEX,
  SOURCE_SC_REGEX, INCLUDE_CLAIM_REGEX, EXCLUDE_CLAIM_REGEX, SET_DEFAULT_SC, RUN_SMOKE_TEST,
  COPY_IMAGE, BACKUP_BASE_DIR, WORKDIR_OVERRIDE, WORKLOAD_STOP_TIMEOUT,
  WORKLOAD_READY_TIMEOUT, COPY_TIMEOUT, STEP_PAUSES, ALLOW_DEGRADED, ALSO_SCALE,
  DATA_BACKUP_SC, SKIP_SECRETS_BACKUP, SKIP_UNSUPPORTED_CLAIMS,
  KEEP_FINALIZERS, KEEP_DATA_BACKUPS, FINALIZER

After a clean dry-run, re-run with --execute --yes to perform the migration.
EOF
}

require_arg_value() {
  local opt="$1" value="${2-}"
  [[ -n "${value}" && "${value}" != --* ]] || die "Missing value for ${opt}"
  printf '%s' "${value}"
}

trim_string() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<< "$1"
}

yaml_scalar_value() {
  local value
  value="$(trim_string "$1")"
  if [[ "${value}" != \"* && "${value}" != \'* ]]; then
    value="${value%%#*}"
    value="$(trim_string "${value}")"
  fi
  if [[ ( "${value}" == \"* && "${value}" == *\" ) || ( "${value}" == \'* && "${value}" == *\' ) ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "${value}"
}

yes_no_from_yaml_bool() {
  local key="$1" value="$2"
  case "${value,,}" in
    true|yes|y|1|on)  printf 'yes' ;;
    false|no|n|0|off) printf 'no' ;;
    *) die "Invalid boolean for ${key}: ${value}" ;;
  esac
}

confirm_step() {
  local title="$1"
  shift || true

  is_dry_run && return 0
  [[ "${STEP_PAUSES}" == "yes" ]] || return 0

  log "STEP PAUSE: ${title}"
  local detail
  for detail in "$@"; do
    [[ -n "${detail}" ]] || continue
    log "  ${detail}"
  done

  if [[ -r /dev/tty ]]; then
    printf 'Press Enter to continue, or Ctrl-C to stop: ' > /dev/tty
    IFS= read -r _ < /dev/tty || die "Unable to read confirmation from terminal"
  else
    printf 'Press Enter to continue, or Ctrl-C to stop: '
    IFS= read -r _ || die "Unable to read confirmation from stdin"
  fi
  log "Confirmed: ${title}"
}

apply_config_value() {
  local key="$1" value="$2"
  case "${key}" in
    execution.confirm) CONFIRM="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;
    execution.dryRun)  DRY_RUN="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;
    execution.stepPauses) STEP_PAUSES="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;

    cluster.kubeconfigPath) KUBECONFIG_PATH="${value}" ;;

    migration.sourceStorageClass)
      SOURCE_SC="${value}"
      SOURCE_SC_REGEX=""
      ;;
    migration.sourceStorageClassRegex)
      SOURCE_SC_REGEX="${value}"
      SOURCE_SC=""
      ;;
    migration.targetStorageClass) TARGET_SC="${value}" ;;
    migration.setDefaultStorageClass) SET_DEFAULT_SC="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;
    migration.runSmokeTest) RUN_SMOKE_TEST="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;
    migration.copyImage) COPY_IMAGE="${value}" ;;
    migration.dataBackupStorageClass) DATA_BACKUP_SC="${value}" ;;
    migration.keepDataBackups) KEEP_DATA_BACKUPS="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;
    migration.backupBaseDir) BACKUP_BASE_DIR="${value}" ;;
    migration.workloadStopTimeout) WORKLOAD_STOP_TIMEOUT="${value}" ;;
    migration.workloadReadyTimeout) WORKLOAD_READY_TIMEOUT="${value}" ;;
    migration.copyTimeout) COPY_TIMEOUT="${value}" ;;
    migration.skipUnsupportedClaims) SKIP_UNSUPPORTED_CLAIMS="$(yes_no_from_yaml_bool "${key}" "${value}")" ;;

    scope.includeNamespacesRegex) INCLUDE_NS_REGEX="${value}" ;;
    scope.excludeNamespacesRegex) EXCLUDE_NS_REGEX="${value}" ;;
    scope.includeClaimsRegex) INCLUDE_CLAIM_REGEX="${value}" ;;
    scope.excludeClaimsRegex) EXCLUDE_CLAIM_REGEX="${value}" ;;

    handlers.imageRegistry.enabled|handlers.clusterMonitoring.enabled)
      if [[ "$(yes_no_from_yaml_bool "${key}" "${value}")" == "yes" ]]; then
        die "${key}=true is not supported by this script revision"
      fi
      ;;
  esac
}

load_config_file() {
  local file="$1"
  [[ -r "${file}" ]] || die "Cannot read config file: ${file}"

  local line indent key value level full_key i
  local -a yaml_keys=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "${line}" =~ ^([[:space:]]*)([A-Za-z_][A-Za-z0-9_]*):[[:space:]]*(.*)$ ]] || continue

    indent="${#BASH_REMATCH[1]}"
    key="${BASH_REMATCH[2]}"
    value="${BASH_REMATCH[3]}"
    (( indent % 2 == 0 )) || die "Unsupported YAML indentation in ${file}: ${line}"
    level=$((indent / 2))

    yaml_keys[${level}]="${key}"
    for ((i = level + 1; i < 8; i++)); do
      unset "yaml_keys[${i}]"
    done

    [[ -n "$(trim_string "${value}")" ]] || continue
    value="$(yaml_scalar_value "${value}")"

    full_key="${yaml_keys[0]}"
    for ((i = 1; i <= level; i++)); do
      full_key+=".${yaml_keys[${i}]}"
    done
    apply_config_value "${full_key}" "${value}"
  done < "${file}"
}

preload_config_from_args() {
  while (($# > 0)); do
    case "$1" in
      -c|--config)
        CONFIG_FILE="$(require_arg_value "$1" "${2-}")"
        load_config_file "${CONFIG_FILE}"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      -c|--config)           CONFIG_FILE="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --dry-run)              DRY_RUN="yes"; shift ;;
      --execute)              DRY_RUN="no"; shift ;;
      --yes)                  YES_FLAG="yes"; CONFIRM="yes"; shift ;;
      --cleanup-finalizers)   CLEANUP_FINALIZERS_ONLY="yes"; shift ;;
      --kube-bin)             KUBE_BIN="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --kubeconfig)           KUBECONFIG_PATH="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --source-sc)            SOURCE_SC="$(require_arg_value "$1" "${2-}")"; SOURCE_SC_REGEX=""; shift 2 ;;
      --source-sc-regex)      SOURCE_SC_REGEX="$(require_arg_value "$1" "${2-}")"; SOURCE_SC=""; shift 2 ;;
      --target-sc|--destination-sc) TARGET_SC="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --namespace)            INCLUDE_NS_REGEX="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --exclude-ns)           EXCLUDE_NS_REGEX="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --claim)                INCLUDE_CLAIM_REGEX="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --exclude-claim)        EXCLUDE_CLAIM_REGEX="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --no-set-default)       SET_DEFAULT_SC="no"; shift ;;
      --no-smoke-test)        RUN_SMOKE_TEST="no"; shift ;;
      --copy-image)           COPY_IMAGE="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --backup-dir)           BACKUP_BASE_DIR="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --workdir)              WORKDIR_OVERRIDE="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --workload-stop-timeout)  WORKLOAD_STOP_TIMEOUT="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --workload-ready-timeout) WORKLOAD_READY_TIMEOUT="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --copy-timeout)         COPY_TIMEOUT="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --no-step-pauses)       STEP_PAUSES="no"; shift ;;
      --step-pauses)          STEP_PAUSES="yes"; shift ;;
      --allow-degraded)       ALLOW_DEGRADED="yes"; shift ;;
      --also-scale)           ALSO_SCALE="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --data-backup-sc)       DATA_BACKUP_SC="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      --delete-data-backups-after-restore) KEEP_DATA_BACKUPS="no"; shift ;;
      --skip-secrets-backup)  SKIP_SECRETS_BACKUP="yes"; shift ;;
      --skip-unsupported-claims) SKIP_UNSUPPORTED_CLAIMS="yes"; shift ;;
      --keep-finalizers)      KEEP_FINALIZERS="yes"; shift ;;
      --finalizer)            FINALIZER="$(require_arg_value "$1" "${2-}")"; shift 2 ;;
      -h|--help)              usage; exit 0 ;;
      *)                      die "Unknown argument: $1" ;;
    esac
  done

  if [[ "${CLEANUP_FINALIZERS_ONLY}" == "yes" ]]; then
    if ! is_dry_run; then
      [[ "${CONFIRM}" == "yes" ]] || die "Refusing to run --cleanup-finalizers --execute without CONFIRM=yes (or --yes)"
    fi
    return 0
  fi

  [[ -n "${SOURCE_SC}" || -n "${SOURCE_SC_REGEX}" ]] || die "Missing --source-sc or --source-sc-regex"
  [[ -n "${TARGET_SC}" ]] || die "Missing --target-sc"
  [[ -z "${SOURCE_SC}" || "${SOURCE_SC}" != "${TARGET_SC}" ]] || die "Source and target StorageClass must differ"

  if ! is_dry_run; then
    [[ "${CONFIRM}" == "yes" ]] || die "Refusing to run --execute without CONFIRM=yes (or --yes)"
  fi
}


# -----------------------------------------------------------------------------
# Finalizer helpers
# -----------------------------------------------------------------------------

add_finalizer() {
  local kind="$1" ns="$2" name="$3"

  if is_dry_run; then
    if [[ -n "${ns}" ]]; then
      dry_log "would add finalizer ${FINALIZER} to ${kind}/${name} in namespace ${ns}"
    else
      dry_log "would add finalizer ${FINALIZER} to ${kind}/${name}"
    fi
    return 0
  fi

  local finalizers
  if [[ -n "${ns}" ]]; then
    finalizers="$(
      kc -n "${ns}" get "${kind}" "${name}" -o json \
        | jq -c --arg f "${FINALIZER}" '
            .metadata.finalizers // []
            | if index($f) then . else . + [$f] end
          '
    )"
    kc -n "${ns}" patch "${kind}" "${name}" --type=merge \
      -p "$(jq -nc --argjson f "${finalizers}" '{metadata:{finalizers:$f}}')" >/dev/null
  else
    finalizers="$(
      kc get "${kind}" "${name}" -o json \
        | jq -c --arg f "${FINALIZER}" '
            .metadata.finalizers // []
            | if index($f) then . else . + [$f] end
          '
    )"
    kc patch "${kind}" "${name}" --type=merge \
      -p "$(jq -nc --argjson f "${finalizers}" '{metadata:{finalizers:$f}}')" >/dev/null
  fi
}

remove_finalizer() {
  local kind="$1" ns="$2" name="$3"

  if is_dry_run; then
    if [[ -n "${ns}" ]]; then
      dry_log "would remove finalizer ${FINALIZER} from ${kind}/${name} in namespace ${ns}"
    else
      dry_log "would remove finalizer ${FINALIZER} from ${kind}/${name}"
    fi
    return 0
  fi

  local finalizers
  if [[ -n "${ns}" ]]; then
    if ! kc -n "${ns}" get "${kind}" "${name}" >/dev/null 2>&1; then
      return 0
    fi
    finalizers="$(
      kc -n "${ns}" get "${kind}" "${name}" -o json \
        | jq -c --arg f "${FINALIZER}" '.metadata.finalizers // [] | map(select(. != $f))'
    )"
    kc -n "${ns}" patch "${kind}" "${name}" --type=merge \
      -p "$(jq -nc --argjson f "${finalizers}" '{metadata:{finalizers:$f}}')" >/dev/null
  else
    if ! kc get "${kind}" "${name}" >/dev/null 2>&1; then
      return 0
    fi
    finalizers="$(
      kc get "${kind}" "${name}" -o json \
        | jq -c --arg f "${FINALIZER}" '.metadata.finalizers // [] | map(select(. != $f))'
    )"
    kc patch "${kind}" "${name}" --type=merge \
      -p "$(jq -nc --argjson f "${finalizers}" '{metadata:{finalizers:$f}}')" >/dev/null
  fi
}

record_protected_source_pv() {
  local pv="$1"
  [[ -n "${PROTECTED_SOURCE_PVS_FILE}" ]] || return 0
  is_dry_run && return 0
  printf '%s\n' "${pv}" >> "${PROTECTED_SOURCE_PVS_FILE}"
}


# -----------------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------------

check_prerequisites() {
  detect_kube_binary
  require_bin jq
  require_bin awk
  require_bin sed
  require_bin date

  if [[ -n "${KUBECONFIG_PATH}" ]]; then
    [[ -r "${KUBECONFIG_PATH}" ]] || die "Cannot read kubeconfig: ${KUBECONFIG_PATH}"
  fi

  kc cluster-info >/dev/null 2>&1 || die "Cannot reach cluster with the chosen kubeconfig"

  if [[ "${CLEANUP_FINALIZERS_ONLY}" == "yes" ]]; then
    return 0
  fi

  if [[ -n "${SOURCE_SC}" ]]; then
    kc get sc "${SOURCE_SC}" >/dev/null 2>&1 || die "Source StorageClass not found: ${SOURCE_SC}"
  else
    local source_sc_matches
    if ! source_sc_matches="$(
      kc get sc -o json | jq -r --arg re "${SOURCE_SC_REGEX}" '
        .items[].metadata.name | select(test($re))
      '
    )"; then
      die "Invalid --source-sc-regex: ${SOURCE_SC_REGEX}"
    fi
    [[ -n "${source_sc_matches}" ]] || die "No StorageClass matches source regex: ${SOURCE_SC_REGEX}"
    if grep -Fxq "${TARGET_SC}" <<< "${source_sc_matches}"; then
      die "Source StorageClass regex also matches target StorageClass ${TARGET_SC}: ${SOURCE_SC_REGEX}"
    fi
    log "Source StorageClass regex matched: $(tr '\n' ' ' <<< "${source_sc_matches}" | sed 's/[[:space:]]*$//')"
  fi
  kc get sc "${TARGET_SC}" >/dev/null 2>&1 || die "Target StorageClass not found: ${TARGET_SC}"
  if [[ -n "${DATA_BACKUP_SC}" ]]; then
    kc get sc "${DATA_BACKUP_SC}" >/dev/null 2>&1 || die "Data backup StorageClass not found: ${DATA_BACKUP_SC}"
  fi
}

cluster_has_co() {
  kc api-resources --api-group=config.openshift.io -o name 2>/dev/null \
    | grep -q '^clusteroperators\.config\.openshift\.io$'
}

cluster_has_mcp() {
  kc api-resources --api-group=machineconfiguration.openshift.io -o name 2>/dev/null \
    | grep -q '^machineconfigpools\.machineconfiguration\.openshift\.io$'
}

check_cluster_health() {
  if cluster_has_co; then
    local unhealthy
    unhealthy="$(
      kc get co -o json | jq -r '
        .items[]
        | select(
            ([.status.conditions[] | select(.type=="Available") | .status] | first) != "True"
            or ([.status.conditions[] | select(.type=="Progressing") | .status] | first) != "False"
            or ([.status.conditions[] | select(.type=="Degraded") | .status] | first) != "False"
          )
        | .metadata.name
      '
    )"
    if [[ -n "${unhealthy}" ]]; then
      if [[ "${ALLOW_DEGRADED}" == "yes" ]]; then
        log "WARNING: ClusterOperators not fully healthy (--allow-degraded set):"
        printf '%s\n' "${unhealthy}"
      else
        printf '%s\n' "${unhealthy}" >&2
        die "Some ClusterOperators are not fully healthy. Re-run with --allow-degraded to override."
      fi
    fi
  else
    log "ClusterOperators API not present, skipping CO health check"
  fi

  if cluster_has_mcp; then
    local updating
    updating="$(
      kc get mcp -o json | jq -r '
        .items[]
        | select((.status.conditions[]? | select(.type=="Updating") | .status) == "True")
        | .metadata.name
      '
    )"
    [[ -z "${updating}" ]] || die "MachineConfigPool currently Updating: ${updating}"
  fi
}


# -----------------------------------------------------------------------------
# Discovery
# -----------------------------------------------------------------------------

discover_candidate_pvcs() {
  kc get pvc -A -o json | jq -r \
    --arg src "${SOURCE_SC}" \
    --arg src_re "${SOURCE_SC_REGEX}" \
    --arg tgt "${TARGET_SC}" \
    --arg ns_re "${INCLUDE_NS_REGEX}" \
    --arg ns_ex "${EXCLUDE_NS_REGEX}" \
    --arg c_re "${INCLUDE_CLAIM_REGEX}" \
    --arg c_ex "${EXCLUDE_CLAIM_REGEX}" '
      .items[]
      | select(.status.phase == "Bound")
      | select(
          if $src_re != "" then
            ((.spec.storageClassName // "") | test($src_re))
          else
            ((.spec.storageClassName // "") == $src)
          end
        )
      | select((.spec.storageClassName // "") != $tgt)
      | select(.metadata.namespace | test($ns_re))
      | select((.metadata.namespace | test($ns_ex)) | not)
      | select(.metadata.name | test($c_re))
      | select((.metadata.name | test($c_ex)) | not)
      | [
          .metadata.namespace,
          .metadata.name,
          (.spec.storageClassName // ""),
          .spec.volumeName,
          (.spec.volumeMode // "Filesystem"),
          (.spec.resources.requests.storage // ""),
          (.spec.accessModes | join(","))
        ]
      | @tsv
    '
}

refresh_impacted_namespaces() {
  IMPACTED_NAMESPACES=()
  ((${#CANDIDATE_ROWS[@]} > 0)) || return 0
  mapfile -t IMPACTED_NAMESPACES < <(
    printf '%s\n' "${CANDIDATE_ROWS[@]}" | cut -f1 | sort -u
  )
}

load_candidate_plan() {
  mapfile -t CANDIDATE_ROWS < <(discover_candidate_pvcs)

  if ((${#CANDIDATE_ROWS[@]} == 0)); then
    if [[ -n "${SOURCE_SC_REGEX}" ]]; then
      log "No candidate PVCs found for source SC regex=${SOURCE_SC_REGEX} in scope ns=${INCLUDE_NS_REGEX} claim=${INCLUDE_CLAIM_REGEX}"
    else
      log "No candidate PVCs found for SC=${SOURCE_SC} in scope ns=${INCLUDE_NS_REGEX} claim=${INCLUDE_CLAIM_REGEX}"
    fi
    return 0
  fi

  refresh_impacted_namespaces

  log "Discovered ${#CANDIDATE_ROWS[@]} candidate PVC(s) across ${#IMPACTED_NAMESPACES[@]} namespace(s)"
}

validate_candidates() {
  local row mode ns claim has_block=0
  local -a supported_rows=()
  for row in "${CANDIDATE_ROWS[@]}"; do
    ns="$(tsv_get "${row}" 1)"
    claim="$(tsv_get "${row}" 2)"
    mode="$(tsv_get "${row}" 5)"
    if [[ "${mode}" == "Block" ]]; then
      if [[ "${SKIP_UNSUPPORTED_CLAIMS}" == "yes" ]]; then
        log "Skipping unsupported volumeMode=Block PVC: ${ns}/${claim}"
        continue
      else
        log "Unsupported volumeMode=Block: ${ns}/${claim}"
        has_block=1
      fi
    fi
    supported_rows+=("${row}")
  done
  [[ "${has_block}" == "0" ]] || die "Block-mode PVCs are not supported by this script."
  if ((${#supported_rows[@]} > 0)); then
    CANDIDATE_ROWS=("${supported_rows[@]}")
  else
    CANDIDATE_ROWS=()
  fi
  refresh_impacted_namespaces
}

parse_gib() {
  local raw="${1:-0}"
  case "${raw}" in
    *Ti) printf '%d\n' "$((${raw%Ti} * 1024))" ;;
    *Gi) printf '%d\n' "${raw%Gi}" ;;
    *Mi) printf '%d\n' "$(( ${raw%Mi} / 1024 ))" ;;
    *Ki) printf '%d\n' "$(( ${raw%Ki} / 1024 / 1024 ))" ;;
    *)   printf '0\n' ;;
  esac
}

print_candidate_plan() {
  if ((${#CANDIDATE_ROWS[@]} == 0)); then
    log "Candidate plan is empty"
    return 0
  fi
  log "Candidate plan:"
  local row total_gi=0 size_raw size_gi
  printf '%-30s  %-60s  %-8s  %-12s  %s\n' "NAMESPACE" "PVC" "SIZE" "MODE" "PV"
  for row in "${CANDIDATE_ROWS[@]}"; do
    size_raw="$(tsv_get "${row}" 6)"
    size_gi="$(parse_gib "${size_raw}")"
    total_gi=$((total_gi + size_gi))
    printf '%-30s  %-60s  %-8s  %-12s  %s\n' \
      "$(tsv_get "${row}" 1)" "$(tsv_get "${row}" 2)" \
      "${size_raw}"          "$(tsv_get "${row}" 5)" \
      "$(tsv_get "${row}" 4)"
  done
  log "Total declared capacity: ${total_gi} GiB across ${#CANDIDATE_ROWS[@]} PVC(s)"
}

claims_for_namespace() {
  local ns="$1" row
  for row in "${CANDIDATE_ROWS[@]}"; do
    if [[ "$(tsv_get "${row}" 1)" == "${ns}" ]]; then
      printf '%s\n' "$(tsv_get "${row}" 2)"
    fi
  done
}

source_pv_for_claim() {
  local ns="$1" claim="$2" row
  for row in "${CANDIDATE_ROWS[@]}"; do
    if [[ "$(tsv_get "${row}" 1)" == "${ns}" && "$(tsv_get "${row}" 2)" == "${claim}" ]]; then
      printf '%s\n' "$(tsv_get "${row}" 4)"
      return 0
    fi
  done
}

pods_using_claims() {
  local ns="$1"; shift
  local re; re="$(join_alt "$@")"
  kc -n "${ns}" get pods -o json | jq -r --arg re "^(${re})$" '
    .items[]
    | select(.metadata.deletionTimestamp == null)
    | . as $p
    | ($p.spec.volumes[]? | select(.persistentVolumeClaim))
    | select(.persistentVolumeClaim.claimName | test($re))
    | [$p.metadata.name, .persistentVolumeClaim.claimName, $p.status.phase] | @tsv
  ' || true
}

resolve_top_controller() {
  local ns="$1" pod="$2" kind name parent_kind parent_name
  kind="$(kc -n "${ns}" get pod "${pod}" -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null || true)"
  name="$(kc -n "${ns}" get pod "${pod}" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || true)"

  if [[ -z "${kind}" || -z "${name}" ]]; then
    printf 'Pod\t%s\n' "${pod}"
    return 0
  fi

  case "${kind}" in
    ReplicaSet)
      parent_kind="$(kc -n "${ns}" get rs "${name}" -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null || true)"
      parent_name="$(kc -n "${ns}" get rs "${name}" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || true)"
      if [[ "${parent_kind}" == "Deployment" && -n "${parent_name}" ]]; then
        printf 'Deployment\t%s\n' "${parent_name}"
      else
        printf 'ReplicaSet\t%s\n' "${name}"
      fi
      ;;
    ReplicationController)
      parent_kind="$(kc -n "${ns}" get rc "${name}" -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null || true)"
      parent_name="$(kc -n "${ns}" get rc "${name}" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || true)"
      if [[ "${parent_kind}" == "DeploymentConfig" && -n "${parent_name}" ]]; then
        printf 'DeploymentConfig\t%s\n' "${parent_name}"
      else
        printf 'ReplicationController\t%s\n' "${name}"
      fi
      ;;
    Deployment|StatefulSet|DeploymentConfig|DaemonSet)
      printf '%s\t%s\n' "${kind}" "${name}"
      ;;
    *)
      printf '%s\t%s\n' "${kind}" "${name}"
      ;;
  esac
}

discover_top_workloads_for_claims() {
  local ns="$1"; shift
  local users pod
  users="$(pods_using_claims "${ns}" "$@")"
  [[ -n "${users}" ]] || return 0
  while IFS=$'\t' read -r pod _ _; do
    [[ -n "${pod}" ]] || continue
    resolve_top_controller "${ns}" "${pod}"
  done <<< "${users}" | sort -u
}


# -----------------------------------------------------------------------------
# Backup workspace — auto-discovers what to dump
# -----------------------------------------------------------------------------

refresh_workdir() {
  if [[ -n "${WORKDIR_OVERRIDE}" ]]; then
    WORKDIR="${WORKDIR_OVERRIDE}"
  else
    WORKDIR="${BACKUP_BASE_DIR}/pvc-storageclass-migration-$(date +%Y%m%d-%H%M%S)"
  fi
  RESULTS_TSV="${WORKDIR}/migrated-pvcs.tsv"
  PROTECTED_SOURCE_PVS_FILE="${WORKDIR}/protected-source-pvs.txt"
  DATA_BACKUPS_TSV="${WORKDIR}/data-backup-pvcs.tsv"
}

# Returns the list of namespaced API resource kinds that should be backed up.
# It enumerates everything the cluster reports as namespaced + listable, then
# strips out the kinds that are either noisy (events), runtime-only
# (authorization/authentication reviews), live metrics, or already covered
# by the cluster-scope dump.
discover_namespaced_kinds() {
  local skip_re='^(events|events\.events\.k8s\.io|.*\.metrics\.k8s\.io|.*\.authorization\.k8s\.io|.*\.authentication\.k8s\.io|bindings|tokenreviews|localsubjectaccessreviews|selfsubjectreviews|selfsubjectaccessreviews|selfsubjectrulesreviews)$'
  kc api-resources --namespaced=true --verbs=list -o name 2>/dev/null \
    | sort -u \
    | grep -Ev "${skip_re}" \
    | { if [[ "${SKIP_SECRETS_BACKUP}" == "yes" ]]; then grep -v '^secrets$'; else cat; fi; }
}

# Cluster-scoped kinds relevant for a storage migration: storage CRs, nodes,
# infrastructure, and the OpenShift status objects (CO/MCP) if present.
discover_cluster_kinds() {
  local candidates=(
    storageclasses.storage.k8s.io
    persistentvolumes
    csidrivers.storage.k8s.io
    csinodes.storage.k8s.io
    volumeattachments.storage.k8s.io
    volumesnapshotclasses.snapshot.storage.k8s.io
    nodes
    clusteroperators.config.openshift.io
    machineconfigpools.machineconfiguration.openshift.io
    infrastructures.config.openshift.io
    clusterversions.config.openshift.io
  )
  local k
  for k in "${candidates[@]}"; do
    if kc get "${k}" --request-timeout=5s --ignore-not-found -o name >/dev/null 2>&1; then
      printf '%s\n' "${k}"
    fi
  done
}

# Dump one (namespace, kind) tuple to a YAML file, returning 1 if the kind
# is empty in that namespace so the caller can skip noise.
backup_namespace_kind() {
  local ns="$1" kind="$2" out_file="$3"
  local count
  count="$(kc -n "${ns}" get "${kind}" --ignore-not-found --no-headers 2>/dev/null | sed '/^$/d' | wc -l || echo 0)"
  (( count > 0 )) || return 1
  kc -n "${ns}" get "${kind}" -o yaml > "${out_file}" 2>/dev/null
  return 0
}

backup_namespace() {
  local ns="$1"
  local out_dir="${WORKDIR}/namespaces/$(namespace_slug "${ns}")"
  log "Backing up namespace ${ns} -> ${out_dir}/"
  mkdir -p "${out_dir}"

  local kind out_file
  while IFS= read -r kind; do
    [[ -n "${kind}" ]] || continue
    out_file="${out_dir}/${kind//\//_}.yaml"
    if backup_namespace_kind "${ns}" "${kind}" "${out_file}"; then
      log "  wrote ${out_file}"
    fi
  done < <(discover_namespaced_kinds)
}

backup_cluster_scope() {
  local out_dir="${WORKDIR}/cluster"
  log "Backing up cluster-scoped resources -> ${out_dir}/"
  mkdir -p "${out_dir}"

  local kind out_file
  while IFS= read -r kind; do
    [[ -n "${kind}" ]] || continue
    out_file="${out_dir}/${kind//\//_}.yaml"
    kc get "${kind}" -o yaml > "${out_file}" 2>/dev/null || true
    if [[ -s "${out_file}" ]]; then
      log "  wrote ${out_file}"
    else
      rm -f "${out_file}"
    fi
  done < <(discover_cluster_kinds)
}

backup_cluster_state() {
  if is_dry_run; then
    dry_log "would create backup directory ${WORKDIR}"
    dry_log "would auto-discover namespaced kinds via '${KUBE_BIN} api-resources --namespaced=true --verbs=list'"
    dry_log "would dump per-namespace kinds for ${#IMPACTED_NAMESPACES[@]} namespace(s): ${IMPACTED_NAMESPACES[*]}"
    dry_log "would dump cluster-scoped kinds for storage migration context"
    [[ "${SKIP_SECRETS_BACKUP}" == "yes" ]] && dry_log "would skip Secrets (--skip-secrets-backup)"
    return 0
  fi

  log "Creating workspace ${WORKDIR}"
  mkdir -p "${WORKDIR}"

  backup_cluster_scope

  local ns
  for ns in "${IMPACTED_NAMESPACES[@]}"; do
    backup_namespace "${ns}"
  done

  : > "${RESULTS_TSV}"
  : > "${PROTECTED_SOURCE_PVS_FILE}"
  : > "${DATA_BACKUPS_TSV}"
}


# -----------------------------------------------------------------------------
# Default StorageClass
# -----------------------------------------------------------------------------

set_default_storageclass() {
  [[ "${SET_DEFAULT_SC}" == "yes" ]] || { log "Skipping default-SC change (--no-set-default)"; return 0; }

  local current_defaults
  current_defaults="$(
    kc get sc -o json | jq -r --arg t "${TARGET_SC}" '
      .items[]
      | select(.metadata.name != $t)
      | select((.metadata.annotations["storageclass.kubernetes.io/is-default-class"] // "false") == "true")
      | .metadata.name
    '
  )"

  if is_dry_run; then
    dry_log "would set StorageClass ${TARGET_SC} default=true (so future PVCs land on it)"
    while IFS= read -r sc; do
      [[ -n "${sc}" ]] || continue
      dry_log "would set StorageClass ${sc} default=false"
    done <<< "${current_defaults}"
    return 0
  fi

  log "Setting ${TARGET_SC} as default StorageClass"
  kc annotate sc "${TARGET_SC}" storageclass.kubernetes.io/is-default-class=true --overwrite

  while IFS= read -r sc; do
    [[ -n "${sc}" ]] || continue
    log "Unsetting default flag on StorageClass ${sc}"
    kc annotate sc "${sc}" storageclass.kubernetes.io/is-default-class=false --overwrite
  done <<< "${current_defaults}"
}


# -----------------------------------------------------------------------------
# Smoke test
# -----------------------------------------------------------------------------

smoke_test_target_sc() {
  [[ "${RUN_SMOKE_TEST}" == "yes" ]] || { log "Skipping smoke test (--no-smoke-test)"; return 0; }

  local provisioner binding_mode
  provisioner="$(kc get sc "${TARGET_SC}" -o jsonpath='{.provisioner}')"
  binding_mode="$(kc get sc "${TARGET_SC}" -o jsonpath='{.volumeBindingMode}')"

  if is_dry_run; then
    dry_log "would create namespace ${SMOKE_NS}, PVC ${SMOKE_PVC}, pod ${SMOKE_POD} on ${TARGET_SC}"
    dry_log "target SC details: provisioner=${provisioner} volumeBindingMode=${binding_mode}"
    return 0
  fi

  log "Running smoke test on ${TARGET_SC}"

  kc create ns "${SMOKE_NS}" --dry-run=client -o yaml | kc apply -f -

  cat <<YAML | kc apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${SMOKE_PVC}
  namespace: ${SMOKE_NS}
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 1Gi
  storageClassName: ${TARGET_SC}
---
apiVersion: v1
kind: Pod
metadata:
  name: ${SMOKE_POD}
  namespace: ${SMOKE_NS}
spec:
  restartPolicy: Never
  containers:
  - name: test
    image: ${COPY_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh","-c","date > /data/marker && sleep 20"]
    volumeMounts:
    - { name: data, mountPath: /data }
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: ${SMOKE_PVC}
YAML

  kc -n "${SMOKE_NS}" wait --for=condition=PodScheduled "pod/${SMOKE_POD}" --timeout=120s
  wait_pvc_bound "${SMOKE_NS}" "${SMOKE_PVC}" 180

  local pv driver
  pv="$(kc -n "${SMOKE_NS}" get pvc "${SMOKE_PVC}" -o jsonpath='{.spec.volumeName}')"
  driver="$(kc get pv "${pv}" -o jsonpath='{.spec.csi.driver}' 2>/dev/null || true)"
  log "Smoke OK: ${SMOKE_NS}/${SMOKE_PVC} -> ${pv} driver=${driver:-<n/a>}"

  kc delete ns "${SMOKE_NS}" --wait=false
}


# -----------------------------------------------------------------------------
# Waiters
# -----------------------------------------------------------------------------

wait_pvc_bound() {
  local ns="$1" claim="$2" timeout="${3:-600}" waited=0 phase
  while (( waited < timeout )); do
    phase="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "${phase}" == "Bound" ]] && return 0
    sleep 5; waited=$((waited+5))
  done
  kc -n "${ns}" describe pvc "${claim}" || true
  die "Timed out waiting for PVC ${ns}/${claim} Bound"
}

wait_pv_released_or_available() {
  local pv="$1" timeout="${2:-600}" waited=0 phase
  while (( waited < timeout )); do
    phase="$(kc get pv "${pv}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "${phase}" == "Released" || "${phase}" == "Available" ]] && return 0
    sleep 3; waited=$((waited+3))
  done
  kc get pv "${pv}" -o yaml || true
  die "Timed out waiting for PV ${pv} Released/Available"
}

wait_pod_succeeded() {
  local ns="$1" pod="$2" timeout="${3:-7200}" waited=0 phase
  while (( waited < timeout )); do
    phase="$(kc -n "${ns}" get pod "${pod}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "${phase}" in
      Succeeded) return 0 ;;
      Failed)
        kc -n "${ns}" describe pod "${pod}" || true
        kc -n "${ns}" logs "${pod}" --all-containers=true || true
        die "Copy pod failed: ${ns}/${pod}"
        ;;
      *) sleep 5; waited=$((waited+5));;
    esac
  done
  kc -n "${ns}" describe pod "${pod}" || true
  die "Timed out waiting for copy pod ${ns}/${pod}"
}

wait_no_pod_uses_claims() {
  local ns="$1" timeout="$2"; shift 2
  local waited=0 users
  while (( waited < timeout )); do
    users="$(pods_using_claims "${ns}" "$@")"
    if [[ -z "${users}" ]]; then return 0; fi
    printf '%s\n' "${users}"
    sleep 5; waited=$((waited+5))
  done
  die "Timed out waiting for pods in ${ns} to release the candidate claims"
}


# -----------------------------------------------------------------------------
# Workload scaling
# -----------------------------------------------------------------------------

save_workload_state() {
  local ns="$1" state_file="$2"; shift 2
  : > "${state_file}"
  local row kind name replicas
  for row in "$@"; do
    [[ -n "${row}" ]] || continue
    kind="$(tsv_get "${row}" 1)"
    name="$(tsv_get "${row}" 2)"
    case "${kind}" in
      Deployment)            replicas="$(kc -n "${ns}" get deploy "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)" ;;
      StatefulSet)           replicas="$(kc -n "${ns}" get sts    "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)" ;;
      DeploymentConfig)      replicas="$(kc -n "${ns}" get dc     "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)" ;;
      ReplicaSet)            replicas="$(kc -n "${ns}" get rs     "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)" ;;
      ReplicationController) replicas="$(kc -n "${ns}" get rc     "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)" ;;
      Pod)                   die "Unsupported bare Pod consumer in ${ns}: ${name}" ;;
      *)                     die "Unsupported workload kind in ${ns}: ${kind}/${name}" ;;
    esac
    [[ -n "${replicas}" ]] || replicas=0
    printf '%s\t%s\t%s\n' "${kind}" "${name}" "${replicas}" >> "${state_file}"
  done
}

scale_workload() {
  local ns="$1" kind="$2" name="$3" replicas="$4"
  case "${kind}" in
    Deployment)            kc -n "${ns}" scale deploy "${name}" --replicas="${replicas}" ;;
    StatefulSet)           kc -n "${ns}" scale sts    "${name}" --replicas="${replicas}" ;;
    DeploymentConfig)      kc -n "${ns}" scale dc     "${name}" --replicas="${replicas}" ;;
    ReplicaSet)            kc -n "${ns}" scale rs     "${name}" --replicas="${replicas}" ;;
    ReplicationController) kc -n "${ns}" scale rc     "${name}" --replicas="${replicas}" ;;
    *) die "Unsupported workload kind: ${kind}" ;;
  esac
}

scale_workloads_from_state() {
  local ns="$1" state_file="$2" mode="$3" target kind name replicas
  while IFS=$'\t' read -r kind name replicas; do
    [[ -n "${kind}" ]] || continue
    if [[ "${mode}" == "down" ]]; then target=0; else target="${replicas}"; fi
    if is_dry_run; then
      dry_log "would scale ${kind}/${name} in ${ns} to ${target} (current ${replicas})"
    else
      log "Scaling ${kind}/${name} in ${ns} to ${target}"
      scale_workload "${ns}" "${kind}" "${name}" "${target}"
    fi
  done < "${state_file}"
}

wait_workloads_ready_from_state() {
  local ns="$1" state_file="$2" timeout="${3:-1800}" waited=0 kind name replicas pending
  while (( waited < timeout )); do
    pending=0
    while IFS=$'\t' read -r kind name replicas; do
      [[ -n "${kind}" ]] || continue
      [[ "${replicas}" != "0" ]] || continue
      case "${kind}" in
        Deployment)
          [[ "$(kc -n "${ns}" get deploy "${name}" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0)" -ge "${replicas}" ]] || pending=1
          ;;
        StatefulSet)
          [[ "$(kc -n "${ns}" get sts    "${name}" -o jsonpath='{.status.readyReplicas}'     2>/dev/null || echo 0)" -ge "${replicas}" ]] || pending=1
          ;;
        DeploymentConfig)
          [[ "$(kc -n "${ns}" get dc     "${name}" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0)" -ge "${replicas}" ]] || pending=1
          ;;
        ReplicaSet)
          [[ "$(kc -n "${ns}" get rs     "${name}" -o jsonpath='{.status.readyReplicas}'     2>/dev/null || echo 0)" -ge "${replicas}" ]] || pending=1
          ;;
        ReplicationController)
          [[ "$(kc -n "${ns}" get rc     "${name}" -o jsonpath='{.status.readyReplicas}'     2>/dev/null || echo 0)" -ge "${replicas}" ]] || pending=1
          ;;
      esac
    done < "${state_file}"
    [[ "${pending}" == "0" ]] && return 0
    sleep 10; waited=$((waited+10))
  done
  die "Timed out waiting for workloads in ${ns} to become ready"
}

apply_also_scale_down() {
  [[ -n "${ALSO_SCALE}" ]] || return 0
  local entry ns kind name replicas state_file="${WORKDIR}/also-scale.tsv"
  is_dry_run || : > "${state_file}"
  local -a entries
  IFS=',' read -r -a entries <<< "${ALSO_SCALE}"
  for entry in "${entries[@]}"; do
    IFS='/' read -r ns kind name <<< "${entry}"
    [[ -n "${ns}" && -n "${kind}" && -n "${name}" ]] || die "Bad --also-scale entry: ${entry} (need ns/Kind/name)"
    case "${kind}" in
      Deployment)            replicas="$(kc -n "${ns}" get deploy "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)" ;;
      StatefulSet)           replicas="$(kc -n "${ns}" get sts    "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)" ;;
      DeploymentConfig)      replicas="$(kc -n "${ns}" get dc     "${name}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)" ;;
      *) die "Unsupported --also-scale kind: ${kind}" ;;
    esac
    if is_dry_run; then
      dry_log "would scale ${kind}/${name} in ${ns} to 0 (--also-scale, current ${replicas})"
    else
      log "ALSO scaling ${kind}/${name} in ${ns} to 0"
      printf '%s\t%s\t%s\t%s\n' "${ns}" "${kind}" "${name}" "${replicas}" >> "${state_file}"
      scale_workload "${ns}" "${kind}" "${name}" 0
    fi
  done
}

restore_also_scale() {
  [[ -n "${ALSO_SCALE}" ]] || return 0
  is_dry_run && return 0
  local state_file="${WORKDIR}/also-scale.tsv" ns kind name replicas
  [[ -f "${state_file}" ]] || return 0
  while IFS=$'\t' read -r ns kind name replicas; do
    [[ -n "${kind}" ]] || continue
    log "Restoring ${kind}/${name} in ${ns} to ${replicas}"
    scale_workload "${ns}" "${kind}" "${name}" "${replicas}"
  done < "${state_file}"
}


# -----------------------------------------------------------------------------
# StatefulSet template patching
# -----------------------------------------------------------------------------

patch_statefulsets_from_state() {
  local ns="$1" state_file="$2" target_sc="$3"
  local kind name count needs_change current_scs
  while IFS=$'\t' read -r kind name _; do
    [[ "${kind}" == "StatefulSet" ]] || continue

    count="$(kc -n "${ns}" get sts "${name}" -o json | jq '.spec.volumeClaimTemplates | length')"
    [[ "${count}" != "0" ]] || continue

    needs_change="$(
      kc -n "${ns}" get sts "${name}" -o json | jq -r --arg sc "${target_sc}" '
        [.spec.volumeClaimTemplates[]? | select((.spec.storageClassName // "") != $sc)] | length
      '
    )"
    [[ "${needs_change}" != "0" ]] || continue

    current_scs="$(
      kc -n "${ns}" get sts "${name}" -o json | jq -r '
        [.spec.volumeClaimTemplates[]?.spec.storageClassName // "<unset>"] | join(",")
      '
    )"

    if is_dry_run; then
      dry_log "would patch StatefulSet ${ns}/${name} volumeClaimTemplates storageClassName=${target_sc} (current=${current_scs})"
      continue
    fi

    local out="${WORKDIR}/$(namespace_slug "${ns}")-${name}-sts.json"
    confirm_step "Patch StatefulSet volumeClaimTemplates for ${ns}/${name}" \
      "Current template StorageClasses: ${current_scs}" \
      "Recreate StatefulSet with --cascade=orphan and storageClassName=${target_sc}" \
      "Pods are already expected to be stopped before this step."
    log "Recreating StatefulSet ${ns}/${name} with volumeClaimTemplates.storageClassName=${target_sc}"
    kc -n "${ns}" get sts "${name}" -o json \
      | jq --arg sc "${target_sc}" '
          del(
            .metadata.uid,
            .metadata.resourceVersion,
            .metadata.generation,
            .metadata.creationTimestamp,
            .metadata.managedFields,
            .status
          )
          | .spec.replicas = 0
          | .spec.volumeClaimTemplates |= map(.spec.storageClassName = $sc)
        ' > "${out}"

    kc -n "${ns}" delete sts "${name}" --cascade=orphan --wait=true
    kc -n "${ns}" apply -f "${out}"
  done < "${state_file}"
}


# -----------------------------------------------------------------------------
# Per-PVC migration primitive
# -----------------------------------------------------------------------------

create_data_pvc() {
  local ns="$1" name="$2" sc="$3" size="$4" mode="$5" access_json="$6" migration_label="$7" original_claim="$8"
  jq -n \
    --arg name "${name}" --arg ns "${ns}" --arg sc "${sc}" \
    --arg size "${size}" --arg mode "${mode}" --arg migration_label "${migration_label}" \
    --arg original "${original_claim}" --arg ts "$(date -Is)" \
    --argjson access "${access_json}" '
    {
      apiVersion:"v1", kind:"PersistentVolumeClaim",
      metadata: {
        name:$name,
        namespace:$ns,
        labels:{ "storage-migration":$migration_label },
        annotations:{
          "storage-migration/original-claim": $original,
          "storage-migration/created-at": $ts
        }
      },
      spec: { accessModes:$access, resources:{ requests:{ storage:$size }},
              storageClassName:$sc, volumeMode:$mode }
    }
  ' | kc apply -f - >/dev/null
}

copy_data_between_claims() {
  local ns="$1" src_claim="$2" dst_claim="$3" copy_pod="$4" timeout="$5" stage="$6"

  log "${stage}: copying ${ns}/${src_claim} -> ${ns}/${dst_claim} with pod ${copy_pod}"
  kc -n "${ns}" delete pod "${copy_pod}" --ignore-not-found --wait=true >/dev/null

  cat <<YAML | kc apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${copy_pod}
  namespace: ${ns}
  labels:
    storage-migration: copy
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 0
  containers:
  - name: copy
    image: ${COPY_IMAGE}
    imagePullPolicy: IfNotPresent
    securityContext:
      runAsUser: 0
      privileged: true
    command: ["/bin/bash","-ceu"]
    args:
    - |
      echo "${stage}-start \$(date -Is)"
      find /dst -xdev -mindepth 1 -exec rm -rf {} +
      tar --xattrs --acls --selinux --numeric-owner -cpf - -C /src . \
        | tar --xattrs --acls --selinux --numeric-owner -xpf - -C /dst
      sync

      manifest() {
        local root="\$1"
        find "\$root" -xdev -mindepth 1 \
          \( -type d -printf 'd\t%P\t0\t\n' \) -o \
          \( -type f -printf 'f\t%P\t%s\t\n' \) -o \
          \( -type l -printf 'l\t%P\t%s\t%l\n' \) -o \
          \( ! -type d ! -type f ! -type l -printf 'o\t%P\t%s\t\n' \) \
          | LC_ALL=C sort
      }

      file_bytes() {
        find "\$1" -xdev -type f -printf '%s\n' \
          | awk '{s += \$1} END {printf "%.0f\n", s + 0}'
      }

      manifest /src > /tmp/src.manifest
      manifest /dst > /tmp/dst.manifest
      src_count=\$(wc -l < /tmp/src.manifest)
      dst_count=\$(wc -l < /tmp/dst.manifest)
      src_file_bytes=\$(file_bytes /src)
      dst_file_bytes=\$(file_bytes /dst)
      src_manifest_hash=\$(sha256sum /tmp/src.manifest | awk '{print \$1}')
      dst_manifest_hash=\$(sha256sum /tmp/dst.manifest | awk '{print \$1}')
      echo "src_count=\$src_count dst_count=\$dst_count src_file_bytes=\$src_file_bytes dst_file_bytes=\$dst_file_bytes"
      echo "src_manifest_hash=\$src_manifest_hash dst_manifest_hash=\$dst_manifest_hash"
      test "\$src_count" = "\$dst_count"
      test "\$src_file_bytes" = "\$dst_file_bytes"
      test "\$src_manifest_hash" = "\$dst_manifest_hash"
      echo "${stage}-complete \$(date -Is)"
    volumeMounts:
    - { name: src, mountPath: /src }
    - { name: dst, mountPath: /dst }
  volumes:
  - name: src
    persistentVolumeClaim:
      claimName: ${src_claim}
  - name: dst
    persistentVolumeClaim:
      claimName: ${dst_claim}
YAML

  wait_pod_succeeded "${ns}" "${copy_pod}" "${timeout}"
  kc -n "${ns}" logs "${copy_pod}" --all-containers=true | tail -5 || true
  kc -n "${ns}" delete pod "${copy_pod}" --wait=true >/dev/null
}

migrate_single_pvc() {
  local ns="$1" claim="$2"

  local current_sc src_pv size mode access_json labels_json annotations_json
  current_sc="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.spec.storageClassName}' 2>/dev/null || true)"

  if [[ "${current_sc}" == "${TARGET_SC}" ]]; then
    log "Skipping ${ns}/${claim}: already on ${TARGET_SC}"
    return 0
  fi

  log "Migrating PVC ${ns}/${claim} from ${current_sc} to ${TARGET_SC}"

  src_pv="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.spec.volumeName}')"
  size="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.spec.resources.requests.storage}')"
  mode="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.spec.volumeMode}')"
  [[ -n "${mode}" ]] || mode="Filesystem"
  [[ "${mode}" != "Block" ]] || die "Block-mode PVCs not supported: ${ns}/${claim}"

  access_json="$(kc -n "${ns}" get pvc "${claim}" -o json | jq -c '.spec.accessModes')"
  labels_json="$(kc -n "${ns}" get pvc "${claim}" -o json | jq -c '.metadata.labels // {}')"
  annotations_json="$(
    kc -n "${ns}" get pvc "${claim}" -o json | jq -c --arg src "${src_pv}" --arg ts "$(date -Is)" '
      (.metadata.annotations // {})
      | del(
          ."pv.kubernetes.io/bind-completed",
          ."pv.kubernetes.io/bound-by-controller",
          ."volume.beta.kubernetes.io/storage-provisioner",
          ."volume.kubernetes.io/storage-provisioner",
          ."volume.kubernetes.io/selected-node"
        )
      + {
          "storage-migration/source-pv": $src,
          "storage-migration/migrated-at": $ts
        }
    '
  )"

  local stamp; stamp="$(date +%s)"
  local backup_sc="${DATA_BACKUP_SC:-${current_sc}}"
  local backup_claim temp_claim backup_copy_pod restore_copy_pod backup_pv target_pv
  backup_claim="$(k8s_temp_name "backup" "${claim}" "${stamp}")"
  temp_claim="$(k8s_temp_name "migrate" "${claim}" "${stamp}")"
  backup_copy_pod="$(k8s_temp_name "backup-copy" "${claim}" "${stamp}")"
  restore_copy_pod="$(k8s_temp_name "restore-copy" "${claim}" "${stamp}")"

  if is_dry_run; then
    local access_modes source_driver source_handle
    access_modes="$(jq -r 'join(",")' <<< "${access_json}")"
    source_driver="$(kc get pv "${src_pv}" -o jsonpath='{.spec.csi.driver}' 2>/dev/null || true)"
    source_handle="$(kc get pv "${src_pv}" -o jsonpath='{.spec.csi.volumeHandle}' 2>/dev/null || true)"
    [[ -n "${source_driver}" ]] || source_driver="$(kc get pv "${src_pv}" -o jsonpath='{.spec.persistentVolumeSource}' 2>/dev/null | head -c 20 || true)"
    [[ -n "${source_handle}" ]] || source_handle="$(kc get pv "${src_pv}" -o jsonpath='{.spec.vsphereVolume.volumePath}' 2>/dev/null || true)"

    dry_log "PVC ${ns}/${claim}: ${current_sc} -> ${TARGET_SC}"
    dry_log "  source PV=${src_pv} driver=${source_driver:-<unknown>} handle/path=${source_handle:-<n/a>} size=${size} accessModes=${access_modes} volumeMode=${mode}"
    dry_log "  would patch source PV ${src_pv} reclaimPolicy=Retain"
    dry_log "  would add finalizer ${FINALIZER} to source PV ${src_pv}"
    dry_log "  would label source PV ${src_pv} storage-migration=backup"
    dry_log "  would create data backup PVC ${ns}/${backup_claim} on ${backup_sc}"
    dry_log "  would run privileged backup pod ${ns}/${backup_copy_pod} image=${COPY_IMAGE} (${claim} -> ${backup_claim})"
    dry_log "  would verify backup file count and byte count"
    dry_log "  would retain and finalizer-protect the backup PV for ${ns}/${backup_claim}"
    dry_log "  would create temp target PVC ${ns}/${temp_claim} on ${TARGET_SC}"
    dry_log "  would run privileged restore pod ${ns}/${restore_copy_pod} image=${COPY_IMAGE} (${backup_claim} -> ${temp_claim})"
    dry_log "  would verify restored file count and byte count"
    dry_log "  would patch new PV reclaimPolicy=Retain and add finalizer ${FINALIZER}"
    dry_log "  would recreate ${ns}/${claim} bound to the newly provisioned ${TARGET_SC} PV"
    if [[ "${KEEP_DATA_BACKUPS}" == "yes" ]]; then
      dry_log "  would keep backup PVC ${ns}/${backup_claim} as an independent data backup"
    else
      dry_log "  would delete backup PVC ${ns}/${backup_claim} after successful restore/rebind"
    fi
    dry_log "  would remove finalizer ${FINALIZER} from the new PV after rebind, reset reclaimPolicy=Delete"
    return 0
  fi

  # 1. Protect the source PV (Retain + finalizer + backup label).
  confirm_step "Start protected backup for ${ns}/${claim}" \
    "Patch PV ${src_pv} reclaimPolicy=Retain." \
    "Add finalizer ${FINALIZER}." \
    "Create backup PVC ${ns}/${backup_claim} on StorageClass ${backup_sc} and copy source data into it."
  kc patch pv "${src_pv}" --type=merge -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null
  add_finalizer pv "" "${src_pv}"
  record_protected_source_pv "${src_pv}"

  kc patch pv "${src_pv}" --type=merge -p "$(jq -nc --arg ns "${ns}" --arg claim "${claim}" --arg ts "$(date -Is)" '
    { metadata: { labels: { "storage-migration":"backup" }, annotations: {
        "storage-migration/original-claim": ($ns + "/" + $claim),
        "storage-migration/migrated-at": $ts
    }}}
  ')" >/dev/null

  # 2. Clean copy pods and temporary target PVC from any aborted attempt with
  #    the same timestamp-derived names. Existing backup PVCs are never removed
  #    here because they may be the only completed copy from an earlier run.
  kc -n "${ns}" delete pod "${backup_copy_pod}"  --ignore-not-found --wait=true >/dev/null
  kc -n "${ns}" delete pod "${restore_copy_pod}" --ignore-not-found --wait=true >/dev/null
  kc -n "${ns}" delete pvc "${temp_claim}"       --ignore-not-found --wait=true >/dev/null
  if kc -n "${ns}" get pvc "${backup_claim}" >/dev/null 2>&1; then
    die "Backup PVC ${ns}/${backup_claim} already exists; refusing to overwrite it"
  fi

  # 3. Create a source-side backup PVC and copy old data into it. This is the
  #    explicit backup phase before anything deletes or rebinds the original PVC.
  create_data_pvc "${ns}" "${backup_claim}" "${backup_sc}" "${size}" "${mode}" "${access_json}" "data-backup" "${ns}/${claim}"
  copy_data_between_claims "${ns}" "${claim}" "${backup_claim}" "${backup_copy_pod}" "${COPY_TIMEOUT}" "backup"
  backup_pv="$(kc -n "${ns}" get pvc "${backup_claim}" -o jsonpath='{.spec.volumeName}')"
  [[ -n "${backup_pv}" ]] || die "Backup PVC ${ns}/${backup_claim} did not bind to a PV"
  kc patch pv "${backup_pv}" --type=merge -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null
  kc patch pv "${backup_pv}" --type=merge -p "$(jq -nc --arg ns "${ns}" --arg claim "${claim}" --arg backup "${backup_claim}" --arg ts "$(date -Is)" '
    { metadata: { labels: { "storage-migration":"data-backup" }, annotations: {
        "storage-migration/original-claim": ($ns + "/" + $claim),
        "storage-migration/backup-claim": ($ns + "/" + $backup),
        "storage-migration/created-at": $ts
    }}}
  ')" >/dev/null
  add_finalizer pv "" "${backup_pv}"
  printf '%s\t%s\t%s\t%s\t%s\n' "${ns}" "${claim}" "${backup_claim}" "${backup_pv}" "${backup_sc}" >> "${DATA_BACKUPS_TSV}"

  # 4. Create the temp PVC on the target SC and restore from the backup PVC.
  create_data_pvc "${ns}" "${temp_claim}" "${TARGET_SC}" "${size}" "${mode}" "${access_json}" "temp-target" "${ns}/${claim}"
  copy_data_between_claims "${ns}" "${backup_claim}" "${temp_claim}" "${restore_copy_pod}" "${COPY_TIMEOUT}" "restore"

  # 5. Protect the freshly provisioned target PV before we drop the temp claim.
  target_pv="$(kc -n "${ns}" get pvc "${temp_claim}" -o jsonpath='{.spec.volumeName}')"
  [[ -n "${target_pv}" ]] || die "Target PVC ${ns}/${temp_claim} did not bind to a PV"
  kc patch pv "${target_pv}" --type=merge -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null
  add_finalizer pv "" "${target_pv}"

  # 6. Tear down original PVC and temp PVC. Source PV becomes Released.
  confirm_step "Rebind original PVC name for ${ns}/${claim}" \
    "Delete original PVC ${ns}/${claim}; source PV ${src_pv} is retained." \
    "Delete temp PVC ${ns}/${temp_claim}; target PV ${target_pv} is retained." \
    "Recreate PVC ${ns}/${claim} bound to target PV ${target_pv} on ${TARGET_SC}."
  kc -n "${ns}" delete pvc "${claim}"    --wait=true >/dev/null
  wait_pv_released_or_available "${src_pv}" 600

  kc -n "${ns}" delete pvc "${temp_claim}" --wait=true >/dev/null
  wait_pv_released_or_available "${target_pv}" 600
  kc patch pv "${target_pv}" --type=json -p='[{"op":"remove","path":"/spec/claimRef"}]' >/dev/null || true

  # 7. Recreate the original PVC name pointing at the target PV.
  jq -n \
    --arg name "${claim}" --arg ns "${ns}" --arg sc "${TARGET_SC}" \
    --arg vol "${target_pv}" --arg size "${size}" --arg mode "${mode}" \
    --argjson access "${access_json}" --argjson labels "${labels_json}" --argjson ann "${annotations_json}" '
    {
      apiVersion:"v1", kind:"PersistentVolumeClaim",
      metadata: { name:$name, namespace:$ns, labels:$labels, annotations:$ann },
      spec: { accessModes:$access, resources:{ requests:{ storage:$size }},
              storageClassName:$sc, volumeName:$vol, volumeMode:$mode }
    }
  ' | kc apply -f - >/dev/null

  wait_pvc_bound "${ns}" "${claim}" 600

  # 8. Restore normal lifecycle on the target PV and drop the protection
  #    finalizer (the new PV is now the regular bound volume).
  kc patch pv "${target_pv}" --type=merge -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' >/dev/null
  remove_finalizer pv "" "${target_pv}"

  if [[ "${KEEP_DATA_BACKUPS}" == "yes" ]]; then
    log "Keeping data backup ${ns}/${backup_claim} on ${backup_sc} (PV=${backup_pv})"
  else
    confirm_step "Delete data backup for ${ns}/${claim}" \
      "Remove finalizer from backup PV ${backup_pv}." \
      "Set backup PV reclaimPolicy=Delete." \
      "Delete backup PVC ${ns}/${backup_claim}."
    log "Deleting data backup ${ns}/${backup_claim} after successful restore"
    remove_finalizer pv "" "${backup_pv}"
    kc patch pv "${backup_pv}" --type=merge -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' >/dev/null
    kc -n "${ns}" delete pvc "${backup_claim}" --wait=false >/dev/null
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${ns}" "${claim}" "${src_pv}" "${backup_claim}" "${backup_pv}" "${target_pv}" >> "${RESULTS_TSV}"
  log "MIGRATED ${ns}/${claim}  oldPV=${src_pv}  backupPVC=${backup_claim} backupPV=${backup_pv}  newPV=${target_pv}"
}


# -----------------------------------------------------------------------------
# Per-namespace orchestration
# -----------------------------------------------------------------------------

migrate_namespace() {
  local ns="$1"; shift
  local claims=("$@")

  log "=== Namespace ${ns}: ${#claims[@]} candidate PVC(s) ==="

  local users
  users="$(pods_using_claims "${ns}" "${claims[@]}")"
  if [[ -n "${users}" ]]; then
    log "Current pods using candidate claims in ${ns}:"
    printf '%s\n' "${users}"
  fi

  local workloads=()
  mapfile -t workloads < <(discover_top_workloads_for_claims "${ns}" "${claims[@]}")
  if ((${#workloads[@]} == 0)); then
    log "No top-level workloads found for the candidate claims in ${ns}"
  else
    log "Top-level workloads for ${ns}:"
    printf '  %s\n' "${workloads[@]}"
  fi

  local state_file="${WORKDIR}/$(namespace_slug "${ns}")-workloads.tsv"
  local dry_run_state_file=""
  if is_dry_run; then
    dry_run_state_file="$(mktemp "${TMPDIR:-/tmp}/pvc-migration-workloads.XXXXXX")"
    state_file="${dry_run_state_file}"
  fi
  if ((${#workloads[@]} > 0)); then
    save_workload_state "${ns}" "${state_file}" "${workloads[@]}"
  else
    save_workload_state "${ns}" "${state_file}"
  fi

  if ((${#workloads[@]} > 0)); then
    confirm_step "Scale workloads down in ${ns}" \
      "Scale discovered workload controllers to 0 before copying PVC data." \
      "Saved replica counts are in ${state_file}."
  fi
  scale_workloads_from_state "${ns}" "${state_file}" down
  if ! is_dry_run; then
    wait_no_pod_uses_claims "${ns}" "${WORKLOAD_STOP_TIMEOUT}" "${claims[@]}"
  fi

  patch_statefulsets_from_state "${ns}" "${state_file}" "${TARGET_SC}"

  local claim
  for claim in "${claims[@]}"; do
    migrate_single_pvc "${ns}" "${claim}"
  done

  if ((${#workloads[@]} > 0)); then
    confirm_step "Restore workloads in ${ns}" \
      "Scale workload controllers back to their saved replica counts." \
      "Wait for readiness up to ${WORKLOAD_READY_TIMEOUT}s."
  fi
  scale_workloads_from_state "${ns}" "${state_file}" restore
  if ! is_dry_run; then
    wait_workloads_ready_from_state "${ns}" "${state_file}" "${WORKLOAD_READY_TIMEOUT}"
  else
    rm -f "${dry_run_state_file}"
  fi
}


# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------

verify_selected_claims() {
  log "Verifying migrated PVCs"
  local row ns claim sc pv driver
  for row in "${CANDIDATE_ROWS[@]}"; do
    ns="$(tsv_get "${row}" 1)"
    claim="$(tsv_get "${row}" 2)"
    sc="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.spec.storageClassName}')"
    [[ "${sc}" == "${TARGET_SC}" ]] || die "PVC ${ns}/${claim} is on ${sc}, expected ${TARGET_SC}"
    pv="$(kc -n "${ns}" get pvc "${claim}" -o jsonpath='{.spec.volumeName}')"
    [[ -n "${pv}" ]] || die "PVC ${ns}/${claim} not bound after migration"
    driver="$(kc get pv "${pv}" -o jsonpath='{.spec.csi.driver}' 2>/dev/null || true)"
    log "  OK ${ns}/${claim} -> ${pv} driver=${driver:-<n/a>} sc=${sc}"
  done
}

verify_impacted_namespaces() {
  log "Verifying pods in impacted namespaces"
  local ns bad
  for ns in "${IMPACTED_NAMESPACES[@]}"; do
    bad="$(
      kc -n "${ns}" get pods -o json | jq -r '
        .items[]
        | select((.status.phase != "Running") and (.status.phase != "Succeeded"))
        | [.metadata.name, .status.phase] | @tsv
      ' 2>/dev/null || true
    )"
    if [[ -n "${bad}" ]]; then
      printf '%s\n' "${bad}"
      log "WARNING: non-Running pods in ${ns} (could be pre-existing)"
    fi
  done
}

verify_cluster_operators_health() {
  cluster_has_co || return 0
  log "Verifying ClusterOperators"
  local unhealthy
  unhealthy="$(
    kc get co -o json | jq -r '
      .items[]
      | select(
          ([.status.conditions[] | select(.type=="Available") | .status] | first) != "True"
          or ([.status.conditions[] | select(.type=="Progressing") | .status] | first) != "False"
          or ([.status.conditions[] | select(.type=="Degraded") | .status] | first) != "False"
        )
      | .metadata.name
    '
  )"
  if [[ -n "${unhealthy}" ]]; then
    printf '%s\n' "${unhealthy}"
    die "Some ClusterOperators are not healthy after migration"
  fi
}


# -----------------------------------------------------------------------------
# Finalizer cleanup (end-of-run or standalone --cleanup-finalizers)
# -----------------------------------------------------------------------------

cleanup_source_pv_finalizers() {
  if [[ "${KEEP_FINALIZERS}" == "yes" ]]; then
    log "Keeping finalizer ${FINALIZER} on source PVs (--keep-finalizers)"
    return 0
  fi

  if is_dry_run; then
    local row pv
    for row in "${CANDIDATE_ROWS[@]}"; do
      pv="$(tsv_get "${row}" 4)"
      dry_log "would remove finalizer ${FINALIZER} from pv/${pv}"
    done
    return 0
  fi

  confirm_step "Remove migration finalizers from retained source PVs" \
    "Remove ${FINALIZER} from source PVs recorded in ${PROTECTED_SOURCE_PVS_FILE}." \
    "The PVs remain retained rollback artifacts labelled storage-migration=backup."
  log "Removing finalizer ${FINALIZER} from migrated source PVs"

  [[ -f "${PROTECTED_SOURCE_PVS_FILE}" ]] || return 0
  local pv
  while IFS= read -r pv; do
    [[ -n "${pv}" ]] || continue
    remove_finalizer pv "" "${pv}"
  done < "${PROTECTED_SOURCE_PVS_FILE}"
}

cleanup_finalizers_standalone() {
  log "Cleanup-finalizers mode: removing ${FINALIZER} from PVs labelled storage-migration=backup"
  local pvs
  pvs="$(kc get pv -l storage-migration=backup -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
  if [[ -z "${pvs}" ]]; then
    log "No PVs labelled storage-migration=backup found"
    return 0
  fi
  local pv
  for pv in ${pvs}; do
    remove_finalizer pv "" "${pv}"
    log "  ${pv}"
  done
}


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

print_summary() {
  log "Migration summary"
  if [[ -s "${RESULTS_TSV}" ]]; then
    column -t -s $'\t' "${RESULTS_TSV}" 2>/dev/null || cat "${RESULTS_TSV}"
  else
    log "No PVCs were migrated"
  fi
  log "Released backup PVs (rollback artifacts):"
  kc get pv -l storage-migration=backup \
    -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,SC:.spec.storageClassName,CAP:.spec.capacity.storage,CLAIM:.metadata.annotations.storage-migration/original-claim \
    --no-headers 2>/dev/null | sort || true
  if [[ "${KEEP_DATA_BACKUPS}" == "yes" ]]; then
    log "Data-backup PVCs retained:"
    kc get pvc -A -l storage-migration=data-backup \
      -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,STATUS:.status.phase,SC:.spec.storageClassName,PV:.spec.volumeName,CLAIM:.metadata.annotations.storage-migration/original-claim \
      --no-headers 2>/dev/null | sort || true
  fi
  log "Workdir: ${WORKDIR}"
}


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
  preload_config_from_args "$@"
  parse_args "$@"
  detect_kube_binary

  if [[ "${CLEANUP_FINALIZERS_ONLY}" == "yes" ]]; then
    log "=== pvc-storageclass-migrate.sh (cleanup-finalizers) ==="
    log "Mode: $(is_dry_run && echo DRY-RUN || echo EXECUTE)"
    check_prerequisites
    confirm_step "Cleanup migration finalizers" \
      "Remove ${FINALIZER} from PVs labelled storage-migration=backup." \
      "This does not delete PVs by itself."
    cleanup_finalizers_standalone
    return 0
  fi

  log "=== pvc-storageclass-migrate.sh ==="
  log "Mode: $(is_dry_run && echo DRY-RUN || echo EXECUTE)"
  if [[ -n "${CONFIG_FILE}" ]]; then
    log "Config file: ${CONFIG_FILE}"
  fi
  log "Kube client: ${KUBE_BIN}"
  if [[ -n "${KUBECONFIG_PATH}" ]]; then
    log "kubeconfig: ${KUBECONFIG_PATH}"
  else
    log "kubeconfig: client default discovery (\$KUBECONFIG or ~/.kube/config)"
  fi
  if [[ -n "${SOURCE_SC_REGEX}" ]]; then
    log "Source SC regex: ${SOURCE_SC_REGEX} -> Target SC: ${TARGET_SC}"
  else
    log "Source SC: ${SOURCE_SC} -> Target SC: ${TARGET_SC}"
  fi
  log "Namespace scope: include=${INCLUDE_NS_REGEX} exclude=${EXCLUDE_NS_REGEX}"
  log "Claim scope:     include=${INCLUDE_CLAIM_REGEX} exclude=${EXCLUDE_CLAIM_REGEX}"
  log "Set default SC: ${SET_DEFAULT_SC}, Smoke test: ${RUN_SMOKE_TEST}"
  log "Skip unsupported claims: ${SKIP_UNSUPPORTED_CLAIMS}"
  if [[ -n "${DATA_BACKUP_SC}" ]]; then
    log "Data backup SC: ${DATA_BACKUP_SC} (keep backups: ${KEEP_DATA_BACKUPS})"
  else
    log "Data backup SC: per-PVC source StorageClass (keep backups: ${KEEP_DATA_BACKUPS})"
  fi
  log "Copy image: ${COPY_IMAGE}"
  if [[ -n "${WORKDIR_OVERRIDE}" ]]; then
    log "Workdir override: ${WORKDIR_OVERRIDE} (used as-is, no timestamp)"
  else
    log "Backup base: ${BACKUP_BASE_DIR} (timestamped subdir per run)"
  fi
  log "Protection finalizer: ${FINALIZER} (keep at end: ${KEEP_FINALIZERS})"
  log "Step pauses: ${STEP_PAUSES}"

  check_prerequisites
  check_cluster_health

  refresh_workdir
  log "Workdir: ${WORKDIR}$(is_dry_run && echo ' (not created in dry-run)' || true)"

  load_candidate_plan
  if ((${#CANDIDATE_ROWS[@]} == 0)); then
    log "Nothing to migrate. Exiting."
    return 0
  fi

  validate_candidates
  if ((${#CANDIDATE_ROWS[@]} == 0)); then
    log "No supported candidate PVCs remain after validation. Exiting."
    return 0
  fi
  print_candidate_plan

  backup_cluster_state
  if [[ "${SET_DEFAULT_SC}" == "yes" ]]; then
    confirm_step "Set default StorageClass to ${TARGET_SC}" \
      "Annotate ${TARGET_SC} as default." \
      "Unset default annotation on other default StorageClasses."
  fi
  set_default_storageclass
  smoke_test_target_sc

  if [[ -n "${ALSO_SCALE}" ]]; then
    confirm_step "Scale extra workloads down" \
      "Apply --also-scale list: ${ALSO_SCALE}."
  fi
  apply_also_scale_down

  local ns ns_claims
  for ns in "${IMPACTED_NAMESPACES[@]}"; do
    mapfile -t ns_claims < <(claims_for_namespace "${ns}")
    migrate_namespace "${ns}" "${ns_claims[@]}"
  done

  if [[ -n "${ALSO_SCALE}" ]]; then
    confirm_step "Restore extra scaled workloads" \
      "Restore workloads captured from --also-scale."
  fi
  restore_also_scale

  if is_dry_run; then
    cleanup_source_pv_finalizers
    log "Dry-run completed successfully. Re-run with --execute --yes to perform the migration."
    return 0
  fi

  verify_selected_claims
  verify_impacted_namespaces
  verify_cluster_operators_health

  cleanup_source_pv_finalizers

  print_summary

  log "Migration completed."
  log "Old PVs remain in Released + Retain with label storage-migration=backup as rollback artifacts."
  if [[ "${KEEP_DATA_BACKUPS}" == "yes" ]]; then
    log "Data-backup PVCs remain Bound with label storage-migration=data-backup as independent backup copies."
  fi
}

main "$@"

# =============================================================================
# ROLLBACK (manual, per PVC)
#
# Each migrated PVC has a corresponding backup PV labelled
# storage-migration=backup whose annotation
# storage-migration/original-claim records the original ns/name. To roll one
# PVC back:
#
#   In the commands below, ${KC} is whichever client you have (oc or kubectl).
#
#   1.  Find the backup PV:
#         ${KC} get pv -l storage-migration=backup \
#           -o jsonpath='{range .items[?(@.metadata.annotations.storage-migration/original-claim=="NAMESPACE/CLAIM")]}{.metadata.name}{"\n"}{end}'
#   2.  Scale the consumer to 0 so nothing is mounting the current claim.
#   3.  Delete the current PVC (the new PV will go Released because reclaim
#       is Delete by default after migration; if you want to keep it, patch
#       it to Retain first).
#   4.  On the backup PV: remove this script's protection finalizer if
#       --keep-finalizers was used, and strip claimRef:
#         ${KC} patch pv BACKUP_PV --type=json \
#           -p='[{"op":"remove","path":"/spec/claimRef"}]'
#   5.  Recreate the PVC with the original name, accessModes, size, and
#       volumeMode, set spec.volumeName=BACKUP_PV and
#       spec.storageClassName equal to the backup PV's storageClassName.
#   6.  Scale the consumer back to its previous replica count.
#
# The whole-namespace rollback is the same loop repeated for every PVC that
# was migrated. StatefulSets whose volumeClaimTemplates were patched to the
# target SC need their template restored to the source SC; the pre-patch
# manifest is saved as <workdir>/<ns_slug>-<sts>-sts.json.
# =============================================================================
