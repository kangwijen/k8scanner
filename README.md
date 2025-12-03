## k8scanner

`k8scanner` is a Kubernetes infrastructure probe scanner that quickly checks common Kubernetes-related endpoints for exposed services and misconfigurations.

It can discover and probe components across:

- Kubernetes API servers
- Kubelet and etcd
- K3s, OpenShift, Rancher, MicroK8s
- Managed Kubernetes (EKS, GKE, AKS)
- Monitoring stacks (Prometheus, Grafana, etc.)
- Service meshes (Istio, Linkerd, Envoy)
- Ingress controllers (NGINX, Traefik, Kong)
- GitOps and CI/CD tooling (Argo CD, Flux)
- Secrets and networking components (Vault, Weave, Calico, etc.)

All probing is done over TCP and HTTP/HTTPS using only the Python standard library.

### Features

- **Multi-target scanning**: Scan one or many IPs / hostnames concurrently.
- **Rich service coverage**: Predefined service groups for common Kubernetes stacks and tooling.
- **Platform detection**: Heuristics to identify platforms such as OpenShift, K3s, Rancher, EKS, GKE, AKS, etc.
- **Vulnerability hints**:
  - Pod listing exposure
  - Secrets listing exposure
  - etcd key/value exposure
  - Docker API exposure
  - Envoy / Istio config dumps
  - Token / OAuth endpoints
- **Flexible output formats**: human-readable table, JSON, CSV, and HTML report.
- **Threaded scanning**: Fast scanning with a configurable thread pool.

### Requirements

- **Python**: 3.x

### Quick Start

Run a basic scan of a single target using the default `core` services (API server, kubelet, etcd):

```bash
python checker.py -t 192.168.1.100
```

Scan multiple IPs / hostnames:

```bash
python checker.py -t 192.168.1.100,192.168.1.101,k8s.example.com
```

Read targets from a file (one per line, `#` for comments):

```bash
python checker.py -f targets.txt
```

### CLI Usage

```bash
python checker.py [OPTIONS]
```
**Target selection (required unless using `--list-services`):**

- **`-t, --targets`**: Comma-separated list of targets (IPs or domains).
- **`-f, --file`**: File containing targets, one per line.

**Service / group selection:**

- **`-s, --services`**: Comma-separated services or service groups to scan.
  - Default: `core`

**Output control:**

- **`-o, --output`**:
  - `table` (default)
  - `json`
  - `csv`
  - `html` (requires `--output-file`)
- **`--output-file`**:
  - For `html`: required, e.g. `--output-file report.html`
  - For `json` / `csv`: optional (otherwise printed to stdout)
- **`-q, --quiet`**:
  - Quiet mode, hide banner and summary (table-only mode).
- **`--show-closed`**:
  - Include closed ports in the output (otherwise hidden by default).

**Performance tuning:**

- **`--timeout`**: Connection timeout in seconds (default: `5`).
- **`--threads`**: Number of concurrent threads (default: `10`).

**Discovery helpers:**

- **`--list-services`**:
  - Print all available service groups and individual services, then exit.

### Service Groups

`k8scanner` defines many service groups so you can focus on specific layers or platforms.

- **`all`**: All defined services (comprehensive scan).
- **`core`**: Kubernetes API server, kubelet, etcd.
- **`kubernetes`**: Core components plus dashboard.
- **`k3s`**: K3s-specific endpoints plus kubelet and etcd.
- **`openshift`**: OpenShift API, OAuth, monitoring, kubelet.
- **`rancher`**: Rancher server, Rancher agents, plus core Kubernetes services.
- **`microk8s`**: MicroK8s API, kubelet, controller manager, scheduler, agent.
- **`cloud`**: EKS, GKE, AKS, plus core Kubernetes services.
- **`monitoring`**: Prometheus, Alertmanager, Grafana, Jaeger, Zipkin, Kibana, Elasticsearch.
- **`mesh`**: Service mesh components (Envoy, Istio, Linkerd, Kiali).
- **`runtime`**: Container runtime APIs (Docker, containerd, cAdvisor).
- **`gitops`**: Argo CD, Argo Workflows, Argo Events, Flux.
- **`ingress`**: NGINX ingress, Traefik, Kong.
- **`security`**: Secrets-related services (Vault) plus API server.
- **`network`**: Weave Scope, Weave Net, Calico metrics.

You can combine groups and individual services:

```bash
python checker.py -t 10.0.0.1 -s kubernetes,monitoring
python checker.py -t 10.0.0.1 -s all --show-closed
```

### Output Formats

#### Table (default)

Human-readable grouped output per target, sorted by severity (CRITICAL → HIGH → …).

```bash
python checker.py -t 10.0.0.1
```
Shows, for each endpoint:

- Service name and port
- Status (severity-tagged)
- Detected platform (if any)
- HTTP status code
- Version (if identified)
- Truncated response body

#### JSON

Machine-readable JSON array of results, suitable for scripting and further processing:

```bash
python checker.py -t 10.0.0.1 -o json --output-file results.json
```

#### CSV

Simple CSV for spreadsheets and basic tooling:

```bash
python checker.py -t 10.0.0.1 -o csv --output-file results.csv
```

#### HTML Report

Generates a dark-theme HTML dashboard with:

- Summary statistics by severity
- Detected platforms
- Per-target sections with sortable tables

```bash
python checker.py -t 10.0.0.1 -o html --output-file report.html
```
Open the resulting `report.html` in a browser to explore the findings.

### Example Commands

Some practical examples:

- **Single target, core services:**

  ```bash
  python checker.py -t 192.168.1.100
  ```

- **Multiple targets, OpenShift-specific scan:**

  ```bash
  python checker.py -t 10.0.0.1,10.0.0.2 -s openshift
  ```

- **Cloud-managed clusters + monitoring:**

  ```bash
  python checker.py -t k8s.example.com -s cloud,monitoring
  ```

- **Comprehensive scan with closed ports shown:**

  ```bash
  python checker.py -t 10.0.0.1 -s all --show-closed
  ```

### Notes and Limitations

- The tool uses unauthenticated HTTP/HTTPS probes and basic TCP port checks; it does not use kubeconfig or in-cluster authentication.
- Findings (especially CRITICAL/HIGH) should be validated and triaged in context before remediation.
- Self-signed certificates are accepted; hostname verification is disabled for scanning convenience.
