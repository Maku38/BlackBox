# ⬛ BlackBox: eBPF Time-Travel Debugger for Kubernetes

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![eBPF](https://img.shields.io/badge/eBPF-Enabled-success.svg)](https://ebpf.io/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-DaemonSet-326ce5.svg)](https://kubernetes.io/)
[![Linux](https://img.shields.io/badge/Linux-Kernel_5.8%2B-orange.svg)](https://www.kernel.org/)

## 🚀 60-Second Quickstart

Don't believe it works? Try it yourself. We built a one-command demo that spins up a local Kubernetes cluster, deploys the BlackBox eBPF agent, detonates a fork bomb, and automatically triggers the Virtual SRE to diagnose it.

## 🛡️ Enterprise Installation (Helm)

BlackBox is built for strict production environments. The agent runs as a DaemonSet, and the authentication token is securely managed via native Kubernetes Secrets, completely decoupled from the application logic.

```bash
# Install securely via Helm
helm install blackbox ./charts/blackbox \
  --namespace kube-system \
  --set security.authToken="your_highly_secure_token"
```

**Prerequisites:** Docker, `kind`, and `kubectl`.

```bash
git clone https://github.com/Maku38/blackbox.git
cd blackbox
./demo.sh
```

**BlackBox** is a deterministic, zero-overhead "flight recorder" for Kubernetes clusters. Instead of drowning in terabytes of logs *after* a crash, BlackBox uses eBPF to continuously record the exact syscalls and network flows that *led to* the failure. When a pod dies, BlackBox instantly generates a causal graph and feeds it to an LLM for automated root-cause analysis.

## 🎯 The Problem

Your pod OOMKilled at 3 AM. Your logs say nothing. Your metrics are a sea of noise. What actually happened?

Traditional observability tools (Datadog, ELK, Prometheus) are **reactive**:
- By the time your CPU spikes, the rogue process is already dead
- You're left grepping gigabytes of logs, searching for breadcrumbs
- Root cause analysis is manual, slow, and exhausting

## 🚀 The Solution

BlackBox is **deterministic and proactive**:

- **Zero-Overhead Tracing:** eBPF kernel probes capture `sched_process_exec`, `sched_process_exit`, and network flow events directly in the kernel—no userspace context switches
- **Rolling Ring Buffer:** Continuously stores the last N seconds of events in memory. No disk writes. No network overhead. Until an incident occurs.
- **L2 Cgroup Cache:** Standard monitoring agents suffer from TOCTOU (Time-of-Check to Time-of-Use) race conditions where a fork-bomb process dies before the agent can read `/proc/` to identify the container. BlackBox implements an L2 Cgroup Cache in C to reliably tag fast-dying processes with their exact Docker/Kubernetes container ID.
- **Causal Graph AI:** Extracts the exact sequence of events leading up to the crash and feeds it to a local LLM to identify rogue processes, fork bombs, memory leaks, and network anomalies in seconds
- **Kubernetes-Native:** Deployed as a privileged DaemonSet. Works across all nodes. No application instrumentation required.

### 🎬 See It in Action

[![Watch BlackBox catch a K8s Fork Bomb](https://img.youtube.com/vi/cJTSlRwNYGQ/0.jpg)](https://youtu.be/cJTSlRwNYGQ)

*BlackBox detects a fork bomb before the node becomes unresponsive—and identifies the culprit instantly.*

![Project Screenshot](assets/Screenshot%20from%202026-02-24%2000-03-30.png)

---

## 📊 How It Works

### Architecture Overview

BlackBox has three layers:

```
┌─────────────────────────────────────────────────────────────┐
│ Control Plane (Python)                                      │
│ • Fleet Commander: Trigger dumps across cluster             │
│ • Strictly authenticated HTTP API (prevents rogue dumps)     │
│ • Virtual SRE: AI-powered root cause analysis               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ K8s Agent (C, userspace)                                    │
│ • Manages eBPF maps and ring buffers                        │
│ • Exposes authenticated HTTP API (port 8080) for dumps      │
│ • L2 Cgroup Cache: Tags fast-dying processes to containers  │
│ • Runs as privileged DaemonSet on every node                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ eBPF Kernel Probe (C, kernel)                               │
│ • Attached to kernel tracepoints                            │
│ • Captures process exec/exit, network flows                 │
│ • Zero-copy ring buffer (bpf_ringbuf)                       │
└─────────────────────────────────────────────────────────────┘
```

### Event Flow

1. **Continuous Capture:** eBPF probes capture syscalls/network events → kernel ring buffer
2. **Rolling Window:** K8s agent reads buffer in-memory, maintains sliding window of last N events
3. **Incident Trigger:** On crash/OOMKill → dump buffer contents to JSON
4. **AI Analysis:** Fleet Commander ships JSON to Virtual SRE → LLM analyzes causal chain → root cause identified

---

## 🛠 Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **eBPF Kernel Probe** | `src/main.bpf.c` | Captures process and network events at kernel level |
| **K8s Agent** | `src/main.c`, `src/*.h` | Userspace C binary that manages eBPF maps and HTTP API |
| **DaemonSet Manifest** | `k8s/blackbox.yaml` | Kubernetes deployment configuration |
| **Container Image** | `k8s/Dockerfile` | Multi-stage Docker build |
| **Fleet Commander** | `control-plane/commander.py` | Distributed dump trigger across cluster nodes |
| **Virtual SRE** | `control-plane/analyze_real.py` | LLM-powered root cause analyzer |

---

## ⚡ Quick Start (Local Kubernetes)

### Prerequisites

- **Linux kernel 5.8+** (for `eBPF` ringbuf support)
- **Kubernetes cluster** (Kind, K3s, or EKS)
- **Build tools:** `clang`, `llvm`, `libelf-dev`, `libbpf-dev`, `bpftool`
- **Docker** for container builds
- **Python 3.8+** for control plane

### Installation

#### 1️⃣ Build the eBPF Agent

```bash
make
```

This compiles `main.bpf.c` (kernel probe) and `main.c` (userspace agent).

**Output:** `blackbox` (binary in repo root)
- **Zero-Overhead Tracing:** eBPF kernel probes capture `sched_process_exec` and OOM kill events directly in the kernel—no userspace context switches

#### 2️⃣ Containerize & Push

```bash
cd ..
docker build -t blackbox:latest -f k8s/Dockerfile .

# For local Kind cluster:
kind load docker-image blackbox:latest --name <cluster-name>

# For remote registry (e.g., Docker Hub):
docker tag blackbox:latest <your-registry>/blackbox:latest
docker push <your-registry>/blackbox:latest
```

#### 3️⃣ Deploy DaemonSet

```bash
# Update image in k8s/blackbox.yaml if using remote registry
kubectl apply -f k8s/blackbox.yaml

# Verify deployment
kubectl get pods -n kube-system -l app=blackbox -o wide
kubectl logs -n kube-system -l app=blackbox -f
```

#### 4️⃣ Trigger an Incident & Analyze

```bash
cd control-plane

# Set up your AI configuration (Optional)
cp .env.example .env
nano .env # Add your preferred LLM provider and API key

# Trigger a dump on a specific node
python3 commander.py <NODE_INTERNAL_IP>

# Wait for dump file to be generated, then extract it
kubectl cp blackbox/<BLACKBOX_POD_NAME>:/app/<INCIDENT_FILE>.json ./incident.json

# Run the analyzer (Works completely offline if AI is disabled or set to 'local')
python3 analyze_real.py incident.json
```

**Example Output:**
```
[*] Analyzing incident.json...
[+] Root Cause: Process 'fork_bomb' (PID 12345) spawned 500 children in 2 seconds
[+] Impact: Triggered OOMKiller on node k8s-worker-2
[+] Recommendation: Add resource limits to deployment
```

---

## 🔒 Authentication & Security

BlackBox requires an authentication token to trigger cluster dumps, preventing unauthorized access to your kernel telemetry.

### Token Management

**1. Running the Agent in Production:**

Start the agent by passing your secure token via environment variable:

```bash
sudo BLACKBOX_AUTH_TOKEN="your_secure_token_here" ./blackbox
```

**2. Auto-Generated Dev Tokens:**

If you run the agent without the environment variable, BlackBox automatically generates a temporary session token and prints it to stdout:

```
[WARNING] BLACKBOX_AUTH_TOKEN env var not set!
[WARNING] Auto-generated temporary token: dev_7742_1771655109
```

**3. Triggering a Dump:**

Update the `AUTH_TOKEN` variable in `control-plane/commander.py` to match your token:

```python
# filepath: control-plane/commander.py
AUTH_TOKEN = "your_secure_token_here"
```

Or trigger it manually via `curl`:

```bash
curl "http://<NODE_IP>:8080/dump?token=your_secure_token_here"
```

### Best Practices

- **Production:** Use strong, randomly generated tokens (e.g., `openssl rand -hex 32`)
- **Kubernetes:** Store tokens in K8s Secrets, not hardcoded in YAML
- **Rotation:** Change tokens periodically and update all Fleet Commander instances
- **Audit:** Log all dump requests (future roadmap item)

---

## 🗺️ Roadmap

### ✅ Completed
- [x] eBPF process (`sched_process_exec`, `sched_process_exit`) and network tracing
- [x] eBPF process execution tracing (`sched_process_exec`)
- [x] Autonomous OOM kill detection (`kprobe/oom_kill_process`)
- [x] K8s DaemonSet deployment (privileged, all nodes)
- [x] L2 Cgroup Cache for container identification
- [x] Distributed Python Fleet Commander
- [x] Secure API Authentication for the Control Plane trigger
- [x] Local LLM integration (Google Gemini)
- [x] HTTP API for dump triggers

### 🚧 In Progress
- [ ] Native K8s RBAC integration
- [ ] Webhook support for Slack/PagerDuty alerts
- [ ] Grafana dashboard for event timeline visualization

### 📋 Future
- [ ] Multi-cluster aggregation
- [ ] Time-range filtering for incidents
- [ ] Custom eBPF program injection
- [ ] OpenTelemetry integration

---

## 📋 Configuration

### Environment Variables (Virtual SRE)

Configure the AI engine by copying `control-plane/.env.example` to `control-plane/.env`. The AI analysis is **optional**; if not configured, BlackBox will simply output the compressed, deterministic event timeline.

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | `gemini`, `openai`, `claude`, or `local` | `None` (AI disabled) |
| `LLM_API_KEY` | API key for the chosen cloud provider | |
| `LLM_MODEL` | Override the default model | `gemini-2.5-flash` / `gpt-4-turbo` / `llama3` |
| `LLM_BASE_URL` | Endpoint for local models (Ollama, LM Studio) | `http://localhost:11434` |
| `BLACKBOX_AUTH_TOKEN` | Token to trigger remote dumps (Agent env var) | Auto-generated |

### K8s DaemonSet Customization

Edit `k8s/blackbox.yaml`:

```yaml
spec:
  template:
    spec:
      containers:
      - name: blackbox
        env:
        - name: RING_BUFFER_SIZE
          value: "131072"  # Increase for more history
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
```

---

## 🔍 Example: Catching a Fork Bomb

**Scenario:** A pod starts spawning child processes uncontrollably.

**Without BlackBox:**
```
kubectl describe node k8s-worker-2
  Status: NotReady (MemoryPressure)
[guess what happened]
```

**With BlackBox:**
```
$ python3 analyze_real.py incident.json

[+] Incident Timeline:
    14:32:01 - Process 'app' (PID 1234) starts
    14:32:05 - PID 1234 execs to '/usr/bin/fork_bomb' (malicious binary)
    14:32:06 - PID 1234 spawns children: 1235, 1236, 1237... (500 total)
    14:32:08 - Memory usage: 512MB → 8GB in 2 seconds
    14:32:10 - OOMKiller terminates process tree

[!] ROOT CAUSE: Compromised container image with fork bomb payload
[!] RECOMMENDATION: Scan image with Trivy, rotate container registry credentials
```

---

## 🏗️ Building from Source

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install -y \
  clang llvm libelf-dev libdw-dev zlib1g-dev \
  libbpf-dev bpftool linux-headers-$(uname -r)

# Fedora/RHEL
sudo dnf install -y \
  clang llvm elfutils-devel zlib-devel \
  libbpf-devel bpf-tools kernel-devel
```

### Build Steps

```bash
make clean
make
```

**Output:**
- `blackbox` - Main userspace binary
- `src/main.bpf.o` - Compiled eBPF object file

---

## 🧪 Testing

### Integration Test (Local Cluster)

```bash
# Deploy blackbox
kubectl apply -f k8s/blackbox.yaml
sleep 5

# Trigger a test incident
python3 /path/to/trigger_fork_bomb.py

# Wait for dump
sleep 10

# Check logs
kubectl logs -n kube-system -l app=blackbox | grep "DUMP_COMPLETE"
```

---

## 🔐 Security Considerations

- **Privileged Pod:** Requires `privileged: true` to attach eBPF programs. Deploy only in trusted clusters.
- **eBPF Verification:** Kernel eBPF verifier prevents malicious probes from crashing the kernel.
- **No Data Exfiltration:** Ring buffer contents remain in-memory; controlled dump via HTTP API.
- **RBAC:** Control Plane should authenticate via K8s API tokens (future roadmap item).

---

## 🤝 Contributing

BlackBox is a solo project built to solve real Kubernetes debugging pain. I'm actively seeking feedback from:

- **SREs** running production clusters
- **Platform Engineers** managing multi-tenant infrastructure
- **DevOps folks** fighting fires daily

**Found a bug?** Open an issue with:
- Kernel version (`uname -r`)
- Kubernetes version (`kubectl version`)
- Error logs (`dmesg`, pod logs)
- Reproduction steps

**Have an idea?** Submit a discussion or PR.

---

## 📚 Resources

- [eBPF Introduction](https://ebpf.io/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf Docs](https://libbpf.readthedocs.io/)
- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

---

## 📄 License

Apache License 2.0 — See [LICENSE](LICENSE) file.

---

## 🙋 Support

- **GitHub Issues:** Bug reports, feature requests
- **Discussions:** Ideas, architecture questions
- **Email:** maku172004@gmail.com


---

**Built with ❤️ for the Kubernetes community. Made by Mayank Joshi.**