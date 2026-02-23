#!/bin/bash
set -e

# --- BlackBox One-Command Demo ---
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

echo -e "${GREEN}🚀 Initiating BlackBox Zero-to-Hero Demo...${NC}\n"

# 1. Check dependencies
command -v kind >/dev/null 2>&1 || { echo -e "${RED}❌ 'kind' is not installed. Aborting.${NC}" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo -e "${RED}❌ 'kubectl' is not installed. Aborting.${NC}" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${RED}❌ 'docker' is not installed. Aborting.${NC}" >&2; exit 1; }

# 2. Spin up Kind Cluster
echo -e "${GREEN}[1/6] Spinning up local Kubernetes cluster (kind)...${NC}"
kind create cluster --name blackbox-demo || echo "Cluster already exists."

# 3. Build & Load Image
echo -e "\n${GREEN}[2/6] Building eBPF Agent Docker Image...${NC}"
docker build -t blackbox:demo -f k8s/Dockerfile .
kind load docker-image blackbox:demo --name blackbox-demo

# 4. Deploy BlackBox DaemonSet
echo -e "\n${GREEN}[3/6] Deploying BlackBox Kernel Agent...${NC}"
# We inject a known token dynamically for the demo
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: blackbox-agent
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: blackbox
  template:
    metadata:
      labels:
        app: blackbox
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: agent
        image: blackbox:demo
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
        env:
        - name: BLACKBOX_AUTH_TOKEN
          value: "demo_root_7749"
        volumeMounts:
        - name: sys
          mountPath: /sys
        - name: proc
          mountPath: /proc
      volumes:
      - name: sys
        hostPath:
          path: /sys
      - name: proc
        hostPath:
          path: /proc
EOF

echo "Waiting for BlackBox eBPF probes to attach to the kernel..."
kubectl rollout status ds/blackbox-agent -n kube-system --timeout=90s

# 5. Detonate the "Fork Bomb"
echo -e "\n${GREEN}[4/6] Detonating simulated Fork Bomb in isolated Pod...${NC}"
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: rogue-fork-bomb
spec:
  containers:
  - name: attacker
    image: alpine
    command: ["/bin/sh", "-c"]
    # Generates a massive burst of sched_process_exec syscalls
    args: ["echo 'Starting bomb...'; for i in \$(seq 1 1000); do /bin/sh -c 'echo > /dev/null' & done; sleep 10; exit 1"]
EOF

echo "Simulating crash data collection for 5 seconds..."
sleep 5

# 6. Trigger the Dump via Port-Forward
echo -e "\n${GREEN}[5/6] Triggering BlackBox eBPF Dump via Control Plane...${NC}"
kubectl port-forward -n kube-system ds/blackbox-agent 8080:8080 > /dev/null 2>&1 &
PF_PID=$!
sleep 2 # Wait for port-forward to establish

curl -s "http://127.0.0.1:8080/dump?token=demo_root_7749" || true
kill $PF_PID

# 7. Extract & Analyze
echo -e "\n${GREEN}[6/6] Extracting Kernel Telemetry...${NC}"
POD_NAME=$(kubectl get pods -n kube-system -l app=blackbox -o jsonpath='{.items[0].metadata.name}')
JSON_FILE=$(kubectl exec -n kube-system $POD_NAME -- ls | grep incident_ | head -n 1)

if [ -z "$JSON_FILE" ]; then
    echo -e "${RED}❌ Failed to find JSON dump. Did the agent crash?${NC}"
    exit 1
fi

kubectl cp kube-system/$POD_NAME:$JSON_FILE ./$JSON_FILE

echo -e "\n${GREEN}🚀 Passing Telemetry to Virtual SRE (Local AI)...${NC}"
# Feed the extracted JSON file to your Python analyzer
python3 control-plane/analyze_real.py ./$JSON_FILE

echo -e "\n${GREEN}✅ Demo Complete!${NC}"
echo "To clean up your environment, run: kind delete cluster --name blackbox-demo"