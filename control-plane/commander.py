import sys
import concurrent.futures
import requests
import time

# --- FLEET COMMANDER ---
# This simulates your central Control Plane triggering dumps across N nodes.

# MUST MATCH THE TOKEN IN main.c
AUTH_TOKEN = "secret_k8s_7749" 

def trigger_node(ip):
    # Fixed: Added the /dump endpoint and the authentication token
    url = f"http://{ip}:8080/dump?token={AUTH_TOKEN}"
    try:
        # 2-second timeout. If a node is dead, we move on quickly.
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return True, f"[SUCCESS] 🟢 Node {ip:<15} -> Dumped."
        elif response.status_code == 401:
            return False, f"[FAILED]  🔴 Node {ip:<15} -> HTTP 401 (Unauthorized! Check Token)"
        else:
            return False, f"[FAILED]  🔴 Node {ip:<15} -> HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"[OFFLINE] ⭕ Node {ip:<15} -> Unreachable"

def execute_fleet_dump(target_ips):
    print(f"🚀 COMMANDER INITIATING FLEET DUMP ({len(target_ips)} TARGETS)\n" + "-"*50)
    
    start_time = time.time()
    success_count = 0
    
    # Fire requests concurrently (like a real distributed system)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(trigger_node, ip): ip for ip in target_ips}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            success, message = future.result()
            print(message)
            if success:
                success_count += 1
                
    elapsed = time.time() - start_time
    print("-" * 50)
    print(f"🏁 DUMP COMPLETE: {success_count}/{len(target_ips)} nodes captured in {elapsed:.2f}s")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 commander.py <ip1> <ip2> ...")
        print("Example: python3 commander.py 127.0.0.1 10.0.0.5 10.0.0.6")
    else:
        # Strip the script name and pass the IPs
        targets = sys.argv[1:]
        execute_fleet_dump(targets)