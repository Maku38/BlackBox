#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' 

echo -e "${BLUE}⬛ Initializing BlackBox eBPF Flight Recorder...${NC}"

# 1. Check Dependencies
if ! command -v helm &> /dev/null || ! command -v kubectl &> /dev/null; then
    echo "❌ Error: 'helm' and 'kubectl' are required to install BlackBox."
    exit 1
fi

# 2. Generate a Secure Token
# Uses openssl to generate a 32-character random hex string
SECURE_TOKEN=$(openssl rand -hex 16)

# 3. Download to a temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"
echo "📦 Downloading latest BlackBox release..."
# Be sure to replace 'yourusername' with your actual GitHub username!
git clone --depth 1 https://github.com/yourusername/blackbox.git &> /dev/null

# 4. Install via Helm
echo "🛡️ Deploying secure DaemonSet to kube-system..."
helm install blackbox ./blackbox/charts/blackbox \
    --namespace kube-system \
    --set security.authToken="$SECURE_TOKEN" > /dev/null

# 5. Clean up
cd ~
rm -rf "$TMP_DIR"

echo -e "\n${GREEN}✅ BlackBox installed successfully!${NC}"
echo -e "=================================================="
echo -e "🔑 ${BLUE}YOUR SECURE TRIGGER TOKEN: ${NC}$SECURE_TOKEN"
echo -e "=================================================="
echo "Please save this token. You will need it to trigger manual diagnostic dumps."
echo "To check the agent status: kubectl get pods -n kube-system -l app=blackbox"