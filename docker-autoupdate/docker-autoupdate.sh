#!/bin/bash
# docker-autoupdate: updates the docker compose projects running on this host and
# removes old images, keeping the newest KEEP versions per repository (plus any
# image still used by a container).
#
# - Projects are discovered from the labels of RUNNING containers.
# - Only services that are running are pulled and recreated: services stopped on
#   purpose stay stopped.
# - /etc/docker-autoupdate.conf may override the compose file recorded in the
#   container labels (useful when the file was moved). One line per project:
#       <project-name> /path/to/compose.yaml
#
# Usage: docker-autoupdate.sh [--dry-run]
#   --dry-run  print what would be done, change nothing; also reports services
#              whose compose config differs from the running container (they
#              would be recreated even without a new image).
set -uo pipefail

KEEP=${KEEP:-2}
CONF=${DOCKER_AUTOUPDATE_CONF:-/etc/docker-autoupdate.conf}
DRY=0
case "${1:-}" in
  --dry-run) DRY=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

exec 9>/run/docker-autoupdate.lock
flock -n 9 || { echo "another run is in progress, exiting"; exit 0; }

run() { if [ "$DRY" = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }

rc=0
echo "### $(hostname) - update started $(date '+%F %T') (dry-run=$DRY, keep=$KEEP)"

# 1) compose projects with running containers
mapfile -t projects < <(docker ps --filter label=com.docker.compose.project \
  --format '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.Label "com.docker.compose.project.config_files"}}' | sort -u)

for p in "${projects[@]}"; do
  IFS='|' read -r name dir files <<<"$p"
  if [ -f "$CONF" ]; then
    override=$(awk -v n="$name" '$1==n {print $2}' "$CONF")
    if [ -n "$override" ]; then files=$override; dir=$(dirname "$override"); fi
  fi
  args=(-p "$name")
  IFS=',' read -ra fl <<<"$files"
  for f in "${fl[@]}"; do args+=(-f "$f"); done
  mapfile -t services < <(docker ps --filter "label=com.docker.compose.project=$name" \
    --format '{{.Label "com.docker.compose.service"}}' | sort -u)
  echo "== project $name ($files) services: ${services[*]}"
  if [ ! -d "$dir" ]; then echo "!! directory $dir missing, skipping"; rc=1; continue; fi
  for f in "${fl[@]}"; do
    [ -f "$f" ] || { echo "!! compose file $f missing, skipping (see $CONF)"; rc=1; continue 2; }
  done
  if [ "$DRY" = 1 ]; then
    for s in "${services[@]}"; do
      want=$(cd "$dir" && docker compose "${args[@]}" config --hash "$s" 2>/dev/null | awk '{print $2}')
      have=$(docker ps --filter "label=com.docker.compose.project=$name" --filter "label=com.docker.compose.service=$s" \
        --format '{{.Label "com.docker.compose.config-hash"}}' | head -1)
      if [ -n "$want" ] && [ "$want" = "$have" ]; then
        echo "   $s: config unchanged"
      else
        echo "   $s: WARNING config differs from the running container (it would be recreated)"
      fi
    done
  fi
  if ! (cd "$dir" && run docker compose "${args[@]}" pull --quiet "${services[@]}"); then
    echo "!! pull failed for $name: nothing restarted"; rc=1; continue
  fi
  if ! (cd "$dir" && run docker compose "${args[@]}" up -d --no-deps "${services[@]}"); then
    echo "!! up failed for $name"; rc=1
  fi
done

# containers not managed by compose are only reported
docker ps -a --format '{{.Names}} ({{.Image}})|{{.Label "com.docker.compose.project"}}' \
  | sed -n 's/|$//p' | sed 's/^/-- not compose, not updated: /'

# 2) cleanup: per repository keep the newest KEEP images + the ones in use.
#    Old images replaced by a pull lose their tag but keep their digest, so they
#    are grouped by RepoTags[0] or, failing that, RepoDigests[0].
declare -A used=()
while read -r id; do [ -n "$id" ] && used[$id]=1; done < <(docker ps -aq | xargs -r docker inspect --format '{{.Image}}')

declare -A count=()
while IFS='|' read -r repo created id; do
  [ -z "$repo" ] && continue
  count[$repo]=$(( ${count[$repo]:-0} + 1 ))
  if [ -n "${used[$id]:-}" ]; then
    echo "-- keep $repo ${id:7:12} (in use)"
  elif [ "${count[$repo]}" -le "$KEEP" ]; then
    echo "-- keep $repo ${id:7:12} (newest $KEEP, $created)"
  else
    echo "-- remove $repo ${id:7:12} ($created)"
    run docker rmi "$id" >/dev/null || { echo "!! rmi failed for ${id:7:12}"; rc=1; }
  fi
done < <(docker images -aq --no-trunc | sort -u | xargs -r docker image inspect \
  --format '{{if .RepoTags}}{{index .RepoTags 0}}{{else if .RepoDigests}}{{index .RepoDigests 0}}{{end}}|{{.Created}}|{{.Id}}' \
  | awk -F'|' -v OFS='|' '{ sub(/@sha256:[0-9a-f]+$/, "", $1); sub(/:[^:\/]+$/, "", $1); print }' \
  | sort -t'|' -k1,1 -k2,2r)

echo "### done $(date '+%F %T'), rc=$rc"
exit $rc
