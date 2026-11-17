# docker-autoupdate

Weekly, nightly update of the docker compose services running on a host, followed by a cleanup of old images that keeps the newest versions for rollback.

- Discovers compose projects from the labels of **running** containers; only running services are pulled and recreated (`docker compose pull` + `up -d --no-deps`). Services stopped on purpose stay stopped.
- After the update it removes old images, keeping per repository the newest `KEEP` versions (default 2) plus every image still used by a container.
- Runs from a systemd timer with `Persistent=false`: a run missed while the host was off is not caught up during working hours.
- Containers not created by compose are only listed in the log.

On hosts that must not update together (e.g. two reverse proxies), give each one a different `--day`.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/dnviti/k8s-useful-scripts/master/docker-autoupdate/install.sh | sudo bash -s -- --day Mon --time 03:30
```

| Option | Default | Meaning |
|---|---|---|
| `--day` | `Sun` | weekday(s) for `OnCalendar`, e.g. `Mon` or `Mon,Thu` |
| `--time` | `03:30` | time of day |
| `--keep` | `2` | image versions kept per repository |
| `--map "PROJECT /path/compose.yaml"` | – | compose file override (repeatable), see below |
| `--no-enable` | – | install without enabling the timer |
| `--uninstall` | – | disable and remove script and units |

Requires `docker`, the `docker compose` plugin, `curl` and systemd.

## Before enabling it in production

Run a dry run: it changes nothing and shows what the next run would do.

```bash
sudo /usr/local/sbin/docker-autoupdate.sh --dry-run
```

- `WARNING config differs from the running container`: the compose file no longer matches the container, so the service would be recreated even without a new image. Align it first with a manual `docker compose up -d` in a maintenance window.
- `compose file ... missing`: the file recorded in the container labels was moved. Map the project to the new path (keep the **same project name**, otherwise compose would create new, empty named volumes):

```bash
echo "myproject /srv/stack/compose.yaml" | sudo tee -a /etc/docker-autoupdate.conf
```

Do not combine it with a cron `docker system prune`: that deletes the untagged previous versions this tool keeps for rollback.

## Logs

```bash
journalctl -u docker-autoupdate.service
systemctl list-timers docker-autoupdate.timer
```
