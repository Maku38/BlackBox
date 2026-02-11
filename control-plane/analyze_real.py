import json
import sys
import os
import requests

API_KEY = "paste your key here"
# Using Flash model for speed and high rate limits during testing
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

# --- 1. DETERMINISTIC COMPRESSION (Lossless Clustering) ---
def contextualize(raw_data):
    if not raw_data: return []
    
    raw_data.sort(key=lambda x: x['time'])
    crash_time = raw_data[-1]['time']
    
    compressed_timeline = []
    current_cluster = None

    for event in raw_data:
        diff_ns = event['time'] - crash_time
        rel_sec = diff_ns / 1_000_000_000.0
        
        clean_event = {
            "t": f"{rel_sec:.3f}s",
            "pid": event['pid'],
            "comm": event['comm'],
            "ctx": event['context'],
            "type": "NET" if event['type'] == 3 else "EXEC",
            "count": 1
        }
        
        if event['type'] == 3:
            clean_event["dst"] = f"{event['dest_ip']}:{event['dest_port']}"

        # SQUASH sequential identical events to save LLM tokens without losing the anomaly pattern
        if current_cluster and \
           current_cluster['comm'] == clean_event['comm'] and \
           current_cluster['ctx'] == clean_event['ctx'] and \
           current_cluster['type'] == clean_event['type']:
            
            current_cluster['count'] += 1
            current_cluster['t'] = clean_event['t'] # Update to latest time in cluster
        else:
            if current_cluster:
                compressed_timeline.append(current_cluster)
            current_cluster = clean_event

    if current_cluster:
        compressed_timeline.append(current_cluster)

    return compressed_timeline

# --- 2. VIRTUAL SRE ENGINE ---
def query_llm(timeline):
    if not API_KEY:
        print("[!] No API Key found. Run: export LLM_API_KEY='your_key'")
        return None

    system_prompt = """
    You are an elite Linux Kernel Forensic Analyst. Analyze this eBPF flight recorder timeline (T=0 is the dump trigger).
    
    CRITICAL CONTEXT:
    1. If the final events are 'sudo' and 'kill', the dump was MANUALLY TRIGGERED via CLI. State Root Cause as "Manual Diagnostic Trigger".
    2. If the final event is a network connection to port 8080 (often by a python3 or curl process), the dump was TRIGGERED OVER THE NETWORK by the Fleet Commander. State Root Cause as "Remote Diagnostic Trigger via Commander".
    3. Look for Resource Exhaustion: A high 'count' of rapid executions indicates a fork bomb or rogue loop.

    JSON SCHEMA:
    {
        "root_cause": "Specific, factual summary of the anomaly or 'Manual Trigger'.",
        "confidence": "high|medium|low",
        "evidence": ["Fact 1", "Fact 2"],
        "remediation": "Actionable engineering advice."
    }
    """
    
    payload = {
        "contents": [{"parts": [{"text": f"{system_prompt}\n\nTIMELINE DATA:\n{json.dumps(timeline)}"}]}]
    }

    print(f"--- Contacting Virtual SRE (Payload: {len(timeline)} compressed events) ---")
    
    try:
        response = requests.post(f"{API_URL}?key={API_KEY}", json=payload, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']
            return json.loads(raw_text.replace("```json", "").replace("```", "").strip())
        else:
            print(f"API Error: {response.text}")
            return None
    except Exception as e:
        print(f"Request Failed: {e}")
        return None

# --- MAIN ---
def analyze_incident(filename):
    try:
        with open(filename, 'r') as f: raw_data = json.load(f)
    except FileNotFoundError:
        print("File not found.")
        return

    timeline = contextualize(raw_data)
    print(f"Compression ratio: {len(raw_data)} raw events -> {len(timeline)} distinct clusters.")

    report = query_llm(timeline)
    
    if report:
        print("\n=== 🕵️  VIRTUAL SRE REPORT ===")
        print(f"🔴 ROOT CAUSE:  {report.get('root_cause')}")
        print(f"⚖️  CONFIDENCE:  {report.get('confidence')}")
        print("\n🔍 EVIDENCE:")
        for ev in report.get('evidence', []):
            print(f"   - {ev}")
        print(f"\n🛡️  REMEDIATION: {report.get('remediation')}")

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python3 analyze_real.py <incident.json>")
    else: analyze_incident(sys.argv[1])