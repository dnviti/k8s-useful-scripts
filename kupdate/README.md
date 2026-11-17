# kupdate

Rolling Talos Linux upgrade, one release line at a time, with live checks that stop the run at the first problem.

- **Finds the path by itself.** The starting version comes from the nodes. The path goes through the latest patch of every intermediate release line (e.g. `v1.8.0 → v1.8.4 → v1.9.6 → … → v1.13.12`), as Sidero recommends. Releases come from GitHub and the Kubernetes compatibility of each line from the official Talos support matrix. No version is hard-coded.
- **One node at a time**: control planes first, then workers. Each node is cordoned (and annotated `kupdate/cordoned=true`), drained (honouring PodDisruptionBudgets), then upgraded with `talosctl upgrade --wait`. `talosctl` always matches the version running in the cluster and is downloaded and checksum-verified into `~/.local/share/kupdate`. Nodes ahead of a step are skipped, never downgraded.
- **Keeps system extensions.** When the nodes were installed from an Image Factory schematic (e.g. `iscsi-tools` for Longhorn), the installer is `factory.talos.dev/installer/<schematic>:<version>`, even if the machine config still names the vanilla installer. Every installer image is checked to exist before starting. After every node it checks that the extensions, the schematic and the `extraKernelArgs` active before the upgrade (in `/proc/cmdline`) are still there; if not, it stops and leaves that node cordoned.
- **Checks before and after every node**:
  - all nodes Ready and etcd healthy, with every member present and no learners;
  - Longhorn volumes not `degraded`/`faulted`, waiting for replica rebuilds;
  - every Deployment, StatefulSet and DaemonSet that was healthy at the start is ready again;
  - `talosctl health` passes (also before the first change and in `--plan`).
- **Monitors endpoints during the whole run.** It probes every Ingress host plus an optional list of URLs, 4 at a time, every `--interval` seconds, without following redirects (a 3xx counts as an answer). It stops after `--fail-after` failures in a row: connection error, timeout or HTTP 5xx. The probed URLs should resolve to internal addresses: do not monitor URLs behind a WAF or a rate-limited proxy, which could block the probes.
- **No downtime by default.** Before draining a node it refuses to continue if a workload would lose all its ready replicas (single replica, or all replicas on that node) or if a PDB would block the drain. Per-node pods (DaemonSets, Longhorn instance managers) and Job pods are not counted. `--allow-disruption` accepts that downtime, and the endpoints must then recover within `--recover-timeout`.
- **Kubernetes compatibility.** If the next Talos line does not support the running Kubernetes, the run stops there. `--with-k8s` adds the needed `talosctl upgrade-k8s` steps instead: one minor at a time, after a `--dry-run` whose whole output is logged (`--plan` runs the first one too). With talosctl ≥ 1.13 it passes `--manifests-no-prune` unless you give `--k8s-prune`.
- **Safe to interrupt and rerun.** A node upgrade already started is never interrupted: on an error, Ctrl-C, SIGTERM or SIGHUP the run waits for it to finish and then stops. Nodes already on the target version are skipped, so after fixing the cause you just run it again. Nodes cordoned by kupdate are listed when it stops, and the next run uncordons them once Ready. A node cordoned by someone else makes the run refuse to start.
- **Never touches `~/.kube/config` or `$TALOSCONFIG`**: the configs are passed explicitly on every call.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/dnviti/k8s-useful-scripts/master/kupdate/kupdate -o ~/.local/bin/kupdate && chmod +x ~/.local/bin/kupdate
```

Requires Python 3.8+ (stdlib only), `kubectl`, `openssl` and internet access to GitHub, docs.siderolabs.com and dl.k8s.io.

## Use

```bash
kupdate dev --plan          # read-only: checks, upgrade path, images, disruption report
kupdate dev                 # run (asks to type "dev" to confirm)
kupdate prod --to v1.9.6    # stop at a given version
kupdate prod --with-k8s     # include the Kubernetes upgrades the path needs
```

`ENV` maps to `~/.kube/config-ENV` and `~/TalosLinux/ENV/talosconfig`. Override with `--kubeconfig`/`--talosconfig` or `KUPDATE_KUBECONFIG`/`KUPDATE_TALOSCONFIG` (patterns with `{env}`).

Extra URLs to monitor, for example the public URLs of the published services: one per line in `~/.config/kupdate/endpoints-ENV.txt` (or `--endpoints FILE`).

| Option | Default | Meaning |
|---|---|---|
| `--plan` | – | read-only run |
| `--to vX.Y.Z` | newest release | final version |
| `--with-k8s` | off | upgrade Kubernetes when the path needs it |
| `--k8s-prune` | off | let `upgrade-k8s` (talosctl ≥ 1.13) prune bootstrap manifests |
| `--allow-disruption` | off | drain even if a workload loses all ready replicas |
| `--image-repo` | Image Factory schematic | custom installer repository |
| `--interval` / `--fail-after` | 30 s / 3 | endpoint monitor |
| `--drain-timeout` | 20 min | per node |
| `--longhorn-timeout` | 60 min | wait for volumes and workloads after a node |
| `--recover-timeout` | 10 min | endpoints recovery after an allowed disruption |
| `--yes` | off | no confirmation prompt |

Logs: `~/.local/state/kupdate/ENV-<timestamp>.log`, drain output in `~/.local/state/kupdate/ENV-drain-<node>.log`.

## Renew only the admin certificates

```bash
kupdate prod --certs --plan   # show the expiry of the talosconfig and kubeconfig client certificates
kupdate prod --certs          # renew them (asks to type "prod" to confirm)
```

Nothing on the cluster changes: the new certificates are signed by the existing cluster CAs.

1. **Talos certificate.** It is issued with `talosctl config new --roles os:admin` while the old one still works. Once it has expired, it is issued from the cluster `secrets.yaml` instead: `--secrets`, default `~/TalosLinux/ENV/secrets.yaml`.
2. **Kubernetes certificate.** It is issued with `talosctl kubeconfig`.
3. **What gets replaced.** Only the client certificate and key of the **current context** change: the endpoints, CAs, other contexts and other users in the files stay as they were. `~/.kube/config` is updated too when it is an exact copy of the environment's kubeconfig (as made by a context switcher).
4. **Checks and backup.** Both new files are checked against the cluster before anything is replaced, and again afterwards. If the check after the replacement fails, the old files are restored automatically. The old files are kept (mode 600) in `~/.local/state/kupdate/certs-ENV-<timestamp>/backup`: delete that folder once everything works.
5. **Upgrade runs check expiry too.** An upgrade run refuses to start when a certificate expires within 2 days.

| Option | Default | Meaning |
|---|---|---|
| `--certs` | – | certificate renewal only |
| `--crt-ttl` | `8760h` | validity of the new Talos client certificate |
| `--secrets` | `~/TalosLinux/ENV/secrets.yaml` | used only if the Talos certificate already expired |
| `--min-days N` | - | renew only when a certificate expires within N days |

### Automatic renewal

`systemd/` holds a templated service and timer: every day at 10:00 they run `kupdate ENV --certs --yes --min-days 30`, which does nothing until a certificate is 30 days from expiry.

```bash
U=$USER
sed "s/USER/$U/g" systemd/kupdate-certs@.service | sudo tee /etc/systemd/system/kupdate-certs@.service >/dev/null
sudo cp systemd/kupdate-certs@.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kupdate-certs@dev.timer kupdate-certs@prod.timer
sudo systemctl start kupdate-certs@dev.service    # test: logs "nothing to do" while the certificates are valid
journalctl -u 'kupdate-certs@*'
```

Failures (cluster unreachable, verification failed) leave the old files in place and show up as a failed unit: `systemctl --failed`.

## Before the first real run

- Run it inside `tmux` or `screen`, so that a dropped SSH session does not stop it halfway.
- Run `--plan` and read the disruption report. Single-replica workloads (databases, ingress controller, CoreDNS with every replica on one node) make a no-downtime upgrade impossible until they get more replicas or anti-affinity.
- Take etcd and application backups.
- Upgrade the dev cluster first.
- Check the release notes of every line in the path for required manual actions.
