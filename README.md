# ⬛ BlackBox: eBPF Time-Travel Debugger for Kubernetes

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![eBPF](https://img.shields.io/badge/eBPF-Enabled-success.svg)](https://ebpf.io/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-DaemonSet-326ce5.svg)](https://kubernetes.io/)

BlackBox is an open-source, zero-overhead "flight recorder" for Kubernetes. 

Instead of parsing gigabytes of noisy logs *after* an OOMKill or crash, BlackBox uses eBPF ring buffers to continuously record the exact syscalls and network flows *leading up* to the failure. When a pod crashes, BlackBox dumps the causal graph and passes it to an LLM to instantly identify the root cause.

### 🚀 See it in action
**[🔗 Watch BlackBox catch a K8s Fork Bomb]<video width="600" controls>
  <source src="assets/demo.webm" type="video/mp4">
  Your browser does not support the video tag.
</video>**

---

## 🧠 Why BlackBox?
Traditional observability tools (Datadog, ELK, Prometheus) are reactive. By the time your CPU spikes or memory exhausts, the underlying rogue process has already executed and died, leaving you to guess what happened.

BlackBox is deterministic:
* **Zero-Overhead:** Uses eBPF to trace `sched_process_exec` and network events directly in the Linux kernel. 
* **In-Memory Ring Buffer:** Stores a rolling window of recent events. It does not write to disk or clog the network until an incident actually occurs.
* **Causal Graph AI:** Bypasses manual log grepping by feeding the exact pre-crash event timeline to a local LLM to isolate rogue processes, fork bombs, and memory leaks.

## 🏗 Architecture

The system is split into three core components:

1. **The Kernel Probe (`src/main.bpf.c`):** The eBPF program attached to kernel tracepoints.
2. **The K8s Agent (`src/main.c` & `k8s/blackbox.yaml`):** A privileged userspace C agent deployed as a K8s DaemonSet. It manages the eBPF maps and exposes a lightweight port 8080 listener.
3. **The Control Plane (`control-plane/`):** A Python-based Fleet Commander to trigger distributed cluster dumps, and the Virtual SRE (`analyze_real.py`) for automated root-cause analysis.

---

## ⚙️ Quick Start (Local Kubernetes)

### 1. Build the eBPF Agent
You need a Linux environment with `clang`, `libbpf-dev`, and `bpftool` installed.
```bash
cd src
make
2. Containerize & Load into Cluster
Build the Docker image and load it into your local cluster (e.g., Kind).

Bash
cd ..
docker build -t blackbox:local -f k8s/Dockerfile .
kind load docker-image blackbox:local --name <your-cluster-name>
3. Deploy the DaemonSet
Deploy the agent across your Kubernetes nodes.

Bash
kubectl apply -f k8s/blackbox.yaml
kubectl get pods -o wide # Wait for STATUS: Running
4. Trigger an Incident & Analyze
Use the Fleet Commander to trigger a rolling buffer dump over the cluster network.

Bash
cd control-plane
# Trigger the dump on the target Node IP
python3 commander.py <NODE_INTERNAL_IP>

# Extract the JSON payload from the Pod
kubectl cp default/<BLACKBOX_POD_NAME>:/app/<GENERATED_INCIDENT_FILE>.json ./incident.json

# Run the AI Virtual SRE analysis
python3 analyze_real.py incident.json
🗺️ Roadmap
[x] eBPF process & network tracing.

[x] K8s DaemonSet bypass of container isolation.

[x] Distributed Python Commander.

[x] AI Causal Analysis (Local LLM integration).

[ ] Automatic dump triggering on K8s OOMKilled events.

[ ] RBAC integration for the Commander API.

[ ] Webhook support for Slack/PagerDuty alerts.

🤝 Contributing & Feedback
I am a solo developer building this to scratch an itch, and I am actively looking for brutal, unfiltered feedback from SREs, Platform Engineers, and DevOps folks who fight Kubernetes fires daily.

If you think this is awesome, or if you think this would completely break your production cluster—open an issue or reach out. Let's talk.


***

