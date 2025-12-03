import argparse
import ssl
import socket
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Dict, List
import sys
import re

__title__ = "k8scanner"
__author__ = "kangwijen"
__url__ = "https://github.com/kangwijen/k8scanner"
__version__ = "1.0"

# Disable SSL warnings for self-signed certs
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


@dataclass
class ProbeResult:
    target: str
    port: int
    service: str
    status: str
    platform: str = "Unknown"
    response_code: Optional[int] = None
    version: Optional[str] = None
    details: Optional[str] = None
    headers: Dict = field(default_factory=dict)


class KubernetesProber:
    """Probes Kubernetes and related infrastructure endpoints."""
    
    TIMEOUT = 5
    
    # Platform detection patterns
    PLATFORM_SIGNATURES = {
        "OpenShift": [
            "openshift",
            "ocp",
            "redhat",
            "apps.openshift.io",
            "route.openshift.io",
            "oauth-openshift",
        ],
        "K3s": [
            "k3s",
            "+k3s",
        ],
        "Rancher": [
            "rancher",
            "cattle",
            "fleet",
        ],
        "MicroK8s": [
            "microk8s",
            "canonical",
        ],
        "EKS": [
            "eks",
            "amazon",
            "aws",
        ],
        "GKE": [
            "gke",
            "google",
            "gcp",
        ],
        "AKS": [
            "aks",
            "azure",
            "microsoft",
        ],
        "RKE": [
            "rke",
            "rancher kubernetes engine",
        ],
        "Talos": [
            "talos",
            "sidero",
        ],
        "Kind": [
            "kind",
            "kubernetes-in-docker",
        ],
        "Minikube": [
            "minikube",
        ],
    }
    
    # Service definitions by platform
    # Format: (port, service_name, paths, use_ssl)
    SERVICES = {
        # Standard Kubernetes
        "api_server": [
            (6443, "Kubernetes API Server", ["/version", "/healthz", "/api/v1", "/apis"], True),
            (443, "Kubernetes API Server (443)", ["/version", "/healthz", "/api/v1"], True),
            (8080, "Kubernetes API Server (Insecure)", ["/version", "/healthz", "/api/v1"], False),
            (8443, "Kubernetes API Server (8443)", ["/version", "/healthz", "/api/v1"], True),
        ],
        "kubelet": [
            (10250, "Kubelet API (Authenticated)", ["/pods", "/runningpods/", "/healthz", "/metrics"], True),
            (10255, "Kubelet API (Read-Only)", ["/pods", "/spec/", "/healthz", "/metrics"], False),
        ],
        "etcd": [
            (2379, "etcd Client", ["/version", "/health", "/v2/keys", "/v3/kv/range"], False),
            (2380, "etcd Peer", ["/version", "/health"], False),
            (4001, "etcd (Legacy)", ["/version", "/health"], False),
        ],
        "dashboard": [
            (8443, "Kubernetes Dashboard", ["/", "/api/v1/login/status"], True),
            (9090, "Kubernetes Dashboard (Alt)", ["/"], True),
        ],
        
        # K3s Specific
        "k3s": [
            (6443, "K3s API Server", ["/version", "/healthz", "/cacerts"], True),
            (6444, "K3s Supervisor", ["/"], True),
            (10010, "K3s Containerd", ["/"], False),
        ],
        
        # OpenShift Specific
        "openshift": [
            (6443, "OpenShift API Server", [
                "/version",
                "/healthz",
                "/apis/apps.openshift.io/v1",
                "/apis/route.openshift.io/v1",
                "/apis/project.openshift.io/v1",
                "/apis/image.openshift.io/v1",
                "/apis/user.openshift.io/v1",
                "/.well-known/oauth-authorization-server",
            ], True),
            (8443, "OpenShift Console", ["/", "/api/kubernetes/version"], True),
            (443, "OpenShift Router", ["/healthz", "/healthz/ready"], True),
        ],
        "openshift_oauth": [
            (443, "OpenShift OAuth", [
                "/.well-known/oauth-authorization-server",
                "/oauth/authorize",
                "/oauth/token",
            ], True),
            (8443, "OpenShift OAuth (8443)", [
                "/.well-known/oauth-authorization-server",
            ], True),
        ],
        "openshift_monitoring": [
            (9091, "OpenShift Prometheus", ["/api/v1/status/config", "/healthz"], True),
            (9093, "OpenShift Alertmanager", ["/api/v2/status", "/healthz"], True),
            (3000, "OpenShift Grafana", ["/api/health", "/login"], True),
        ],
        
        # Rancher Specific
        "rancher": [
            (443, "Rancher Server", ["/v3", "/v3/settings", "/ping", "/healthz"], True),
            (8443, "Rancher Server (8443)", ["/v3", "/v3/settings", "/ping"], True),
            (80, "Rancher Server (HTTP)", ["/v3", "/ping"], False),
            (9443, "Rancher Webhook", ["/"], True),
        ],
        "rancher_agent": [
            (6443, "Rancher K8s API", ["/version", "/healthz"], True),
            (10250, "Rancher Kubelet", ["/pods", "/healthz"], True),
        ],
        
        # MicroK8s Specific
        "microk8s": [
            (16443, "MicroK8s API Server", ["/version", "/healthz", "/api/v1"], True),
            (10250, "MicroK8s Kubelet", ["/pods", "/healthz"], True),
            (10257, "MicroK8s Controller Manager", ["/healthz"], True),
            (10259, "MicroK8s Scheduler", ["/healthz"], True),
            (25000, "MicroK8s Cluster Agent", ["/"], True),
        ],
        
        # Cloud Managed - EKS
        "eks": [
            (443, "EKS API Server", ["/version", "/healthz", "/api/v1"], True),
            (10250, "EKS Kubelet", ["/pods", "/healthz"], True),
        ],
        
        # Cloud Managed - GKE
        "gke": [
            (443, "GKE API Server", ["/version", "/healthz", "/api/v1"], True),
            (10250, "GKE Kubelet", ["/pods", "/healthz"], True),
        ],
        
        # Cloud Managed - AKS
        "aks": [
            (443, "AKS API Server", ["/version", "/healthz", "/api/v1"], True),
            (10250, "AKS Kubelet", ["/pods", "/healthz"], True),
        ],
        
        # Monitoring & Observability (Common)
        "monitoring": [
            (9090, "Prometheus", ["/api/v1/status/config", "/api/v1/targets", "/-/healthy"], False),
            (9093, "Alertmanager", ["/api/v2/status", "/-/healthy"], False),
            (3000, "Grafana", ["/api/health", "/login"], False),
            (16686, "Jaeger", ["/api/services", "/"], False),
            (9411, "Zipkin", ["/api/v2/services", "/health"], False),
            (5601, "Kibana", ["/api/status", "/app/home"], False),
            (9200, "Elasticsearch", ["/", "/_cluster/health"], False),
        ],
        
        # Service Mesh
        "service_mesh": [
            (15000, "Envoy Admin", ["/server_info", "/clusters", "/config_dump"], False),
            (15001, "Envoy Outbound", ["/"], False),
            (15006, "Envoy Inbound", ["/"], False),
            (15010, "Istiod (gRPC)", ["/"], False),
            (15014, "Istiod Monitoring", ["/metrics", "/debug"], False),
            (15020, "Istio Agent", ["/healthz/ready"], False),
            (15021, "Istio Health", ["/healthz/ready"], False),
            (20001, "Kiali", ["/api/namespaces", "/api/status"], False),
            (8080, "Linkerd Viz", ["/api/version"], False),
        ],
        
        # Container Runtime
        "container_runtime": [
            (2375, "Docker API (Insecure)", ["/version", "/info", "/containers/json"], False),
            (2376, "Docker API (TLS)", ["/version", "/info"], True),
            (10010, "Containerd (CRI)", ["/"], False),
            (8484, "cAdvisor", ["/api/v1.0/containers", "/healthz"], False),
            (4194, "cAdvisor (Legacy)", ["/api/v1.0/containers"], False),
        ],
        
        # CI/CD & GitOps
        "gitops": [
            (443, "Argo CD", ["/api/version", "/healthz"], True),
            (8080, "Argo CD (HTTP)", ["/api/version", "/healthz"], False),
            (2746, "Argo Workflows", ["/api/v1/version"], False),
            (9000, "Flux", ["/healthz", "/metrics"], False),
            (8082, "Argo Events", ["/healthz"], False),
        ],
        
        # Ingress Controllers
        "ingress": [
            (8080, "Nginx Ingress Status", ["/healthz", "/nginx_status", "/configuration"], False),
            (10254, "Nginx Ingress Health", ["/healthz", "/metrics"], False),
            (8404, "Traefik Dashboard", ["/api/overview", "/ping", "/health"], False),
            (9000, "Traefik Metrics", ["/metrics"], False),
            (8000, "Kong Admin", ["/", "/status"], False),
            (8001, "Kong Admin (Alt)", ["/", "/status"], False),
            (8444, "Kong Admin (TLS)", ["/", "/status"], True),
        ],
        
        # Secrets Management
        "secrets": [
            (8200, "Vault", ["/v1/sys/health", "/v1/sys/seal-status"], False),
            (8201, "Vault Cluster", ["/v1/sys/health"], False),
        ],
        
        # Network Visualization
        "network": [
            (4040, "Weave Scope", ["/api/topology", "/api"], False),
            (6781, "Weave Net", ["/status"], False),
            (6782, "Weave Metrics", ["/metrics"], False),
            (9099, "Calico Felix", ["/metrics"], False),
            (9098, "Calico Typha", ["/metrics"], False),
        ],
    }
    
    # Service groups for easy selection
    SERVICE_GROUPS = {
        "all": list(SERVICES.keys()),
        "core": ["api_server", "kubelet", "etcd"],
        "kubernetes": ["api_server", "kubelet", "etcd", "dashboard"],
        "k3s": ["k3s", "kubelet", "etcd"],
        "openshift": ["openshift", "openshift_oauth", "openshift_monitoring", "kubelet"],
        "rancher": ["rancher", "rancher_agent", "api_server", "kubelet"],
        "microk8s": ["microk8s", "etcd"],
        "cloud": ["eks", "gke", "aks", "api_server", "kubelet"],
        "monitoring": ["monitoring"],
        "mesh": ["service_mesh"],
        "runtime": ["container_runtime"],
        "gitops": ["gitops"],
        "ingress": ["ingress"],
        "security": ["secrets", "api_server"],
        "network": ["network"],
    }

    def __init__(self, timeout: int = 5, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        self.results = []

    def _make_request(self, url: str, use_ssl: bool = True) -> tuple:
        """Make HTTP/HTTPS request and return (status_code, response_body, headers)."""
        try:
            req = urllib.request.Request(
                url, 
                headers={
                    "User-Agent": f"{__title__} - K8s-Probe v{__version__}",
                    "Accept": "application/json, */*",
                }
            )
            ctx = ssl_context if use_ssl else None
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                headers = dict(response.headers)
                body = response.read().decode("utf-8", errors="ignore")
                return response.getcode(), body, headers
        except urllib.error.HTTPError as e:
            headers = dict(e.headers) if hasattr(e, 'headers') else {}
            body = ""
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except:
                pass
            return e.code, body if body else str(e.reason), headers
        except urllib.error.URLError as e:
            return None, str(e.reason), {}
        except socket.timeout:
            return None, "Connection timed out", {}
        except Exception as e:
            return None, str(e), {}

    def _check_port_open(self, host: str, port: int) -> bool:
        """Quick TCP port check."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    def _detect_platform(self, body: str, headers: dict, service: str) -> str:
        """Detect the Kubernetes platform/distribution."""
        combined = (body + str(headers) + service).lower()
        
        for platform, signatures in self.PLATFORM_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    return platform
        
        # Check for standard Kubernetes
        if "kubernetes" in combined or "k8s" in combined:
            return "Kubernetes"
        
        return "Unknown"

    def _extract_version(self, body: str, service: str) -> Optional[str]:
        """Extract version info from response body."""
        try:
            data = json.loads(body)
            
            # Kubernetes API Server
            if "gitVersion" in data:
                return data.get("gitVersion")
            
            # etcd
            if "etcdserver" in data:
                return f"etcd {data.get('etcdserver')}"
            if "etcdcluster" in data:
                return f"etcd cluster {data.get('etcdcluster')}"
            
            # Rancher
            if "gitCommit" in data and "version" not in data:
                return data.get("gitCommit", "")[:12]
            if "Version" in data:
                return data.get("Version")
            
            # Generic version field
            if "version" in data:
                v = data.get("version")
                if isinstance(v, str):
                    return v
                elif isinstance(v, dict):
                    return v.get("number", v.get("version", str(v)))
            
            # Docker
            if "Version" in data:
                return f"Docker {data.get('Version')}"
            
        except json.JSONDecodeError:
            # Try regex for version patterns
            patterns = [
                r'version["\s:]+([v\d\.]+)',
                r'gitVersion["\s:]+([v\d\.\-\w]+)',
                r'Server Version[:\s]+([v\d\.]+)',
            ]
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return match.group(1)
        except:
            pass
        return None

    def _analyze_vulnerability(self, status_code: int, body: str, path: str, service: str) -> str:
        """Analyze response for vulnerabilities."""
        body_lower = body.lower()
        
        if status_code == 200:
            # Critical findings
            if any(x in path.lower() for x in ["/pods", "/runningpods"]):
                if len(body) > 100 and ("metadata" in body_lower or "items" in body_lower):
                    return "CRITICAL - Pod List Exposed!"
            
            if "/secrets" in path.lower() and "items" in body_lower:
                return "CRITICAL - Secrets Exposed!"
            
            if any(x in path.lower() for x in ["/exec", "/attach", "/portforward"]):
                return "CRITICAL - Exec/Attach Available!"
            
            if "/v2/keys" in path or "/v3/kv" in path:
                if len(body) > 50:
                    return "CRITICAL - etcd Data Exposed!"
            
            if "/containers/json" in path and len(body) > 100:
                return "CRITICAL - Docker API Exposed!"
            
            if "/config_dump" in path or "/clusters" in path:
                return "HIGH - Envoy Config Exposed!"
            
            if "token" in body_lower and "access" in body_lower:
                return "HIGH - Token Endpoint Accessible!"
            
            # Medium findings
            if "/metrics" in path:
                return "MEDIUM - Metrics Exposed"
            
            if "/healthz" in path or "/health" in path or "/ready" in path:
                return "LOW - Health Check Accessible"
            
            if "/version" in path:
                return "INFO - Version Disclosed"
            
            return "ACCESSIBLE"
        
        elif status_code == 401:
            return "AUTH REQUIRED (401)"
        elif status_code == 403:
            if "system:anonymous" in body_lower:
                return "FORBIDDEN (Anonymous Blocked)"
            return "FORBIDDEN (403)"
        elif status_code == 404:
            return "NOT FOUND (404)"
        elif status_code in [500, 502, 503]:
            return f"SERVER ERROR ({status_code})"
        
        return f"RESPONDED ({status_code})"

    def probe_endpoint(self, target: str, port: int, service: str, paths: list, use_ssl: bool) -> ProbeResult:
        """Probe a single endpoint."""
        protocol = "https" if use_ssl else "http"
        
        # Quick port check first
        if not self._check_port_open(target, port):
            return ProbeResult(
                target=target,
                port=port,
                service=service,
                status="CLOSED",
                platform="N/A",
                details="Port not responding"
            )
        
        # Try each path
        best_result = None
        for path in paths:
            url = f"{protocol}://{target}:{port}{path}"
            status_code, body, headers = self._make_request(url, use_ssl)
            
            if status_code is not None:
                version = self._extract_version(body, service)
                platform = self._detect_platform(body, headers, service)
                status = self._analyze_vulnerability(status_code, body, path, service)
                
                details = body[:300] + "..." if len(body) > 300 else body
                details = details.replace("\n", " ").replace("\r", "").strip()
                
                result = ProbeResult(
                    target=target,
                    port=port,
                    service=service,
                    status=status,
                    platform=platform,
                    response_code=status_code,
                    version=version,
                    details=details,
                    headers=headers
                )
                
                # Prioritize critical/high findings
                if "CRITICAL" in status or "HIGH" in status:
                    return result
                
                # Keep best result (prefer 200 over errors)
                if best_result is None or (status_code == 200 and best_result.response_code != 200):
                    best_result = result
        
        if best_result:
            return best_result
        
        return ProbeResult(
            target=target,
            port=port,
            service=service,
            status="OPEN - No HTTP Response",
            platform="Unknown",
            details="Port open but no valid HTTP response"
        )

    def scan_target(self, target: str, service_types: List[str] = None) -> List[ProbeResult]:
        """Scan a single target for specified services."""
        results = []
        target = target.strip()
        
        if not target:
            return results
        
        # Default to core services
        if service_types is None:
            service_types = ["api_server", "kubelet", "etcd"]
        
        # Expand service groups
        expanded_services = set()
        for svc in service_types:
            if svc in self.SERVICE_GROUPS:
                expanded_services.update(self.SERVICE_GROUPS[svc])
            elif svc in self.SERVICES:
                expanded_services.add(svc)
        
        # Scan each service type
        seen_ports = set()  # Avoid duplicate port scans
        for service_type in expanded_services:
            if service_type not in self.SERVICES:
                continue
            for port, service_name, paths, use_ssl in self.SERVICES[service_type]:
                port_key = (port, use_ssl)
                if port_key in seen_ports:
                    continue
                seen_ports.add(port_key)
                
                result = self.probe_endpoint(target, port, service_name, paths, use_ssl)
                results.append(result)
        
        return results

    def scan_targets(self, targets: List[str], service_types: List[str] = None) -> List[ProbeResult]:
        """Scan multiple targets using thread pool."""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {
                executor.submit(self.scan_target, target, service_types): target
                for target in targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    print(f"[!] Error scanning {target}: {e}", file=sys.stderr)
        
        return all_results


def print_banner():
    """Print tool banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║          k8scanner - Kubernetes Infrastructure Probe Scanner v1.0    ║
    ║    K8s | K3s | OpenShift | Rancher | MicroK8s | EKS | GKE | AKS      ║
    ║            Author: kangwijen | {url}             ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """.format(url=__url__)
    print(banner)


def generate_html_report(results: List[ProbeResult], show_closed: bool = False) -> str:
    """Generate HTML report from scan results."""
    from datetime import datetime
    
    # Filter closed ports if requested
    if not show_closed:
        results = [r for r in results if r.status != "CLOSED"]
    
    # Calculate statistics
    total = len(results)
    critical = sum(1 for r in results if "CRITICAL" in r.status)
    high = sum(1 for r in results if "HIGH" in r.status)
    medium = sum(1 for r in results if "MEDIUM" in r.status)
    low = sum(1 for r in results if "LOW" in r.status or "INFO" in r.status)
    accessible = sum(1 for r in results if "ACCESSIBLE" in r.status)
    auth_required = sum(1 for r in results if "AUTH" in r.status or "FORBIDDEN" in r.status)
    closed = sum(1 for r in results if "CLOSED" in r.status)
    
    # Detect platforms
    platforms = {}
    for r in results:
        if r.platform and r.platform not in ["Unknown", "N/A"]:
            platforms[r.platform] = platforms.get(r.platform, 0) + 1
    
    # Group by target
    by_target = {}
    for r in results:
        if r.target not in by_target:
            by_target[r.target] = []
        by_target[r.target].append(r)
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ACCESSIBLE": 4, "INFO": 5}
    def get_severity(status):
        for key, val in severity_order.items():
            if key in status:
                return val
        return 10
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Infrastructure Scan Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --auth: #8957e5;
            --closed: #484f58;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }}
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, var(--info), var(--critical));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1em;
        }}
        .timestamp {{
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-top: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card.critical {{ border-left: 4px solid var(--critical); }}
        .stat-card.high {{ border-left: 4px solid var(--high); }}
        .stat-card.medium {{ border-left: 4px solid var(--medium); }}
        .stat-card.low {{ border-left: 4px solid var(--low); }}
        .stat-card.info {{ border-left: 4px solid var(--info); }}
        .stat-card.auth {{ border-left: 4px solid var(--auth); }}
        .stat-card.closed {{ border-left: 4px solid var(--closed); }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .stat-card.critical .stat-number {{ color: var(--critical); }}
        .stat-card.high .stat-number {{ color: var(--high); }}
        .stat-card.medium .stat-number {{ color: var(--medium); }}
        .stat-card.low .stat-number {{ color: var(--low); }}
        .stat-card.info .stat-number {{ color: var(--info); }}
        .stat-card.auth .stat-number {{ color: var(--auth); }}
        .stat-card.closed .stat-number {{ color: var(--closed); }}
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .platforms {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .platforms h3 {{
            margin-bottom: 15px;
            color: var(--info);
        }}
        .platform-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .platform-tag {{
            background: var(--bg-tertiary);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            border: 1px solid var(--border-color);
        }}
        .target-section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .target-header {{
            background: var(--bg-tertiary);
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .target-name {{
            font-size: 1.3em;
            font-weight: bold;
            color: var(--info);
        }}
        .target-stats {{
            display: flex;
            gap: 15px;
        }}
        .target-stat {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .target-stat.critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); }}
        .target-stat.high {{ background: rgba(255, 123, 114, 0.2); color: var(--high); }}
        .target-stat.medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium); }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 1px;
        }}
        tr:hover {{
            background: var(--bg-tertiary);
        }}
        .status-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            display: inline-block;
        }}
        .status-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); }}
        .status-high {{ background: rgba(255, 123, 114, 0.2); color: var(--high); }}
        .status-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium); }}
        .status-low {{ background: rgba(63, 185, 80, 0.2); color: var(--low); }}
        .status-info {{ background: rgba(88, 166, 255, 0.2); color: var(--info); }}
        .status-auth {{ background: rgba(137, 87, 229, 0.2); color: var(--auth); }}
        .status-closed {{ background: rgba(72, 79, 88, 0.2); color: var(--closed); }}
        .details {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        .port {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            background: var(--bg-tertiary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .version {{
            color: var(--low);
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.9em;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .target-header {{
                flex-direction: column;
                gap: 10px;
            }}
            table {{
                font-size: 0.85em;
            }}
            th, td {{
                padding: 8px 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Kubernetes Infrastructure Scan Report</h1>
            <p class="subtitle">K8s | K3s | OpenShift | Rancher | MicroK8s | EKS | GKE | AKS</p>
            <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{low}</div>
                <div class="stat-label">Low/Info</div>
            </div>
            <div class="stat-card auth">
                <div class="stat-number">{auth_required}</div>
                <div class="stat-label">Auth Required</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number">{accessible}</div>
                <div class="stat-label">Accessible</div>
            </div>
            <div class="stat-card closed">
                <div class="stat-number">{closed}</div>
                <div class="stat-label">Closed</div>
            </div>
        </div>
'''
    
    # Add platforms section if any detected
    if platforms:
        html += '''
        <div class="platforms">
            <h3>Detected Platforms</h3>
            <div class="platform-tags">
'''
        for platform, count in sorted(platforms.items(), key=lambda x: -x[1]):
            html += f'                <span class="platform-tag">{platform} ({count})</span>\n'
        html += '''            </div>
        </div>
'''
    
    # Add results by target
    for target, target_results in by_target.items():
        target_results.sort(key=lambda x: get_severity(x.status))
        
        # Calculate target-specific stats
        t_critical = sum(1 for r in target_results if "CRITICAL" in r.status)
        t_high = sum(1 for r in target_results if "HIGH" in r.status)
        t_medium = sum(1 for r in target_results if "MEDIUM" in r.status)
        
        html += f'''
        <div class="target-section">
            <div class="target-header">
                <span class="target-name">{target}</span>
                <div class="target-stats">
'''
        if t_critical > 0:
            html += f'                    <span class="target-stat critical">{t_critical} Critical</span>\n'
        if t_high > 0:
            html += f'                    <span class="target-stat high">{t_high} High</span>\n'
        if t_medium > 0:
            html += f'                    <span class="target-stat medium">{t_medium} Medium</span>\n'
        
        html += '''                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Platform</th>
                        <th>Version</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
'''
        
        for r in target_results:
            # Determine status class
            if "CRITICAL" in r.status:
                status_class = "status-critical"
            elif "HIGH" in r.status:
                status_class = "status-high"
            elif "MEDIUM" in r.status:
                status_class = "status-medium"
            elif "LOW" in r.status or "INFO" in r.status:
                status_class = "status-low"
            elif "ACCESSIBLE" in r.status:
                status_class = "status-info"
            elif "AUTH" in r.status or "FORBIDDEN" in r.status:
                status_class = "status-auth"
            else:
                status_class = "status-closed"
            
            # Escape HTML in details
            details = r.details or ""
            details = details.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if len(details) > 100:
                details = details[:100] + "..."
            
            version = r.version or "-"
            platform = r.platform if r.platform not in ["Unknown", "N/A"] else "-"
            
            html += f'''                    <tr>
                        <td>{r.service}</td>
                        <td><span class="port">{r.port}</span></td>
                        <td><span class="status-badge {status_class}">{r.status}</span></td>
                        <td>{platform}</td>
                        <td><span class="version">{version}</span></td>
                        <td class="details" title="{details}">{details}</td>
                    </tr>
'''
        
        html += '''                </tbody>
            </table>
        </div>
'''
    
    html += f'''
        <footer>
            <p>{__title__} - Kubernetes Infrastructure Probe Scanner v{__version__}</p>
            <p>Supports: Kubernetes, K3s, OpenShift, Rancher, MicroK8s, EKS, GKE, AKS</p>
        </footer>
    </div>
</body>
</html>
'''
    return html


def print_results(results: List[ProbeResult], output_format: str = "table", show_closed: bool = False, output_file: str = None):
    """Print scan results."""
    # Filter closed ports if requested
    if not show_closed:
        filtered_results = [r for r in results if r.status != "CLOSED"]
    else:
        filtered_results = results
    
    if output_format == "json":
        output = []
        for r in filtered_results:
            output.append({
                "target": r.target,
                "port": r.port,
                "service": r.service,
                "status": r.status,
                "platform": r.platform,
                "response_code": r.response_code,
                "version": r.version,
                "details": r.details,
            })
        json_output = json.dumps(output, indent=2)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"[+] JSON report saved to: {output_file}")
        else:
            print(json_output)
        return
    
    if output_format == "csv":
        csv_output = "target,port,service,status,platform,response_code,version\n"
        for r in filtered_results:
            csv_output += f'{r.target},{r.port},"{r.service}","{r.status}",{r.platform},{r.response_code or ""},"{r.version or ""}"\n'
        if output_file:
            with open(output_file, 'w') as f:
                f.write(csv_output)
            print(f"[+] CSV report saved to: {output_file}")
        else:
            print(csv_output.strip())
        return
    
    if output_format == "html":
        html_output = generate_html_report(results, show_closed)
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_output)
            print(f"[+] HTML report saved to: {output_file}")
        else:
            print(html_output)
        return
    
    # Table format (default)
    # Group by target
    by_target = {}
    for r in filtered_results:
        if r.target not in by_target:
            by_target[r.target] = []
        by_target[r.target].append(r)
    
    # Sort results within each target by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ACCESSIBLE": 4, "INFO": 5}
    
    def get_severity(status):
        for key, val in severity_order.items():
            if key in status:
                return val
        return 10
    
    # Print table format
    for target, target_results in by_target.items():
        target_results.sort(key=lambda x: get_severity(x.status))
        
        print(f"\n{'='*75}")
        print(f" Target: {target}")
        print(f"{'='*75}")
        
        for r in target_results:
            # Status indicators and colors
            if "CRITICAL" in r.status:
                status_symbol = "[!!!]"
            elif "HIGH" in r.status:
                status_symbol = "[!!]"
            elif "MEDIUM" in r.status:
                status_symbol = "[!]"
            elif "ACCESSIBLE" in r.status or "INFO" in r.status:
                status_symbol = "[+]"
            elif "CLOSED" in r.status:
                status_symbol = "[-]"
            elif "AUTH" in r.status or "FORBIDDEN" in r.status:
                status_symbol = "[~]"
            else:
                status_symbol = "[?]"
            
            print(f"\n  {status_symbol} {r.service} (:{r.port})")
            print(f"      Status: {r.status}")
            if r.platform != "Unknown" and r.platform != "N/A":
                print(f"      Platform: {r.platform}")
            if r.response_code:
                print(f"      HTTP Code: {r.response_code}")
            if r.version:
                print(f"      Version: {r.version}")
            if r.details and "CLOSED" not in r.status and len(r.details) > 0:
                details = r.details[:150] + "..." if len(r.details) > 150 else r.details
                print(f"      Response: {details}")


def print_summary(results: List[ProbeResult]):
    """Print scan summary."""
    total = len(results)
    critical = sum(1 for r in results if "CRITICAL" in r.status)
    high = sum(1 for r in results if "HIGH" in r.status)
    medium = sum(1 for r in results if "MEDIUM" in r.status)
    accessible = sum(1 for r in results if "ACCESSIBLE" in r.status or "INFO" in r.status)
    auth_required = sum(1 for r in results if "AUTH" in r.status or "FORBIDDEN" in r.status)
    closed = sum(1 for r in results if "CLOSED" in r.status)
    
    # Detect platforms
    platforms = {}
    for r in results:
        if r.platform and r.platform not in ["Unknown", "N/A"]:
            platforms[r.platform] = platforms.get(r.platform, 0) + 1
    
    print(f"\n{'='*75}")
    print(" SCAN SUMMARY")
    print(f"{'='*75}")
    print(f"  Total endpoints probed: {total}")
    print(f"  ")
    print(f"  Findings by Severity:")
    print(f"    [!!!] Critical: {critical}")
    print(f"    [!!]  High:     {high}")
    print(f"    [!]   Medium:   {medium}")
    print(f"    [+]   Info:     {accessible}")
    print(f"    [~]   Auth Req: {auth_required}")
    print(f"    [-]   Closed:   {closed}")
    
    if platforms:
        print(f"\n  Detected Platforms:")
        for platform, count in sorted(platforms.items(), key=lambda x: -x[1]):
            print(f"    - {platform}: {count} endpoint(s)")
    
    if critical > 0 or high > 0:
        print(f"\n  [!!!] ALERT: {critical + high} critical/high severity finding(s)!")
        print("  Immediate review recommended.")


def list_services():
    """List available services and groups."""
    print("\nAvailable Service Groups:")
    print("-" * 50)
    for group, services in KubernetesProber.SERVICE_GROUPS.items():
        print(f"  {group:15} -> {', '.join(services[:5])}{'...' if len(services) > 5 else ''}")
    
    print("\n\nAvailable Individual Services:")
    print("-" * 50)
    for service, endpoints in KubernetesProber.SERVICES.items():
        ports = [str(e[0]) for e in endpoints]
        print(f"  {service:20} -> ports: {', '.join(ports)}")


def main():
    parser = argparse.ArgumentParser(
        description=f"{__title__} - Kubernetes Infrastructure Probe Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100
  %(prog)s -t 192.168.1.100,192.168.1.101,k8s.example.com
  %(prog)s -t 10.0.0.1 -s openshift
  %(prog)s -t 10.0.0.1 -s kubernetes,monitoring
  %(prog)s -t 10.0.0.1 -s all --show-closed
  %(prog)s -f targets.txt -o json
  %(prog)s -t 10.0.0.1 -o html --output-file report.html
  %(prog)s -t 10.0.0.1 -o json --output-file results.json
  %(prog)s -t 10.0.0.1 -o csv --output-file results.csv
  %(prog)s --list-services

Service Groups:
  all         - All services (comprehensive scan)
  core        - API Server, Kubelet, etcd
  kubernetes  - Standard K8s components + Dashboard
  k3s         - K3s specific endpoints
  openshift   - OpenShift/OCP specific
  rancher     - Rancher management platform
  microk8s    - MicroK8s specific
  cloud       - EKS, GKE, AKS endpoints
  monitoring  - Prometheus, Grafana, etc.
  mesh        - Istio, Linkerd, Envoy
  gitops      - Argo CD, Flux
  ingress     - Nginx, Traefik, Kong
  security    - Vault, Secrets
  network     - Weave, Calico

Project:
  Name       - {title}
  Author     - {author}
  Repository - {url}
        """.format(title=__title__, author=__author__, url=__url__)
    )
    
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-t", "--targets",
        help="Comma-separated list of targets (IPs or domains)"
    )
    target_group.add_argument(
        "-f", "--file",
        help="File containing targets (one per line)"
    )
    target_group.add_argument(
        "--list-services",
        action="store_true",
        help="List all available services and groups"
    )
    
    parser.add_argument(
        "-s", "--services",
        default="core",
        help="Comma-separated services/groups to scan (default: core)"
    )
    parser.add_argument(
        "-o", "--output",
        choices=["table", "json", "csv", "html"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--output-file",
        help="Save output to file (required for html, optional for json/csv)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only show findings"
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Show closed ports in output"
    )
    
    args = parser.parse_args()
    
    # Handle list services
    if args.list_services:
        list_services()
        sys.exit(0)
    
    # Require targets if not listing
    if not args.targets and not args.file:
        parser.error("Either -t/--targets or -f/--file is required")
    
    # Parse targets
    if args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    else:
        try:
            with open(args.file, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    
    if not targets:
        print("[!] Error: No valid targets provided", file=sys.stderr)
        sys.exit(1)
    
    # Parse services
    services = [s.strip() for s in args.services.split(",") if s.strip()]
    
    # Print banner
    if not args.quiet and args.output in ["table"]:
        print_banner()
        print(f"  Targets: {len(targets)}")
        print(f"  Service Groups: {', '.join(services)}")
        print(f"  Timeout: {args.timeout}s | Threads: {args.threads}")
        print(f"\n  Starting scan...")
    elif args.output == "html" and not args.output_file:
        print("[!] HTML output requires --output-file flag", file=sys.stderr)
        print("    Example: --output-file report.html", file=sys.stderr)
        sys.exit(1)
    
    # Run scan
    prober = KubernetesProber(timeout=args.timeout, threads=args.threads)
    results = prober.scan_targets(targets, services)
    
    # Print results
    print_results(results, args.output, args.show_closed, args.output_file)
    
    # Print summary
    if not args.quiet and args.output == "table":
        print_summary(results)


if __name__ == "__main__":
    main()
