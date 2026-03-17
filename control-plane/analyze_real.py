import json
import sys
import os
import requests
from abc import ABC, abstractmethod

# --- 0. LOAD ENVIRONMENT VARIABLES ---
env_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key.strip()] = value.strip()

# --- 1. DETERMINISTIC COMPRESSION (Lossless Clustering) ---
def contextualize(raw_data):
    if not raw_data: return []
    
    raw_data.sort(key=lambda x: x['timestamp'])
    crash_time = raw_data[-1]['timestamp']
    
    compressed_timeline = []
    current_cluster = None

    for event in raw_data:
        diff_ns = event['timestamp'] - crash_time
        rel_sec = diff_ns / 1_000_000_000.0
        
        is_net = event.get('type') == 'network'
        
        clean_event = {
            "t": f"{rel_sec:.3f}s",
            "pid": event['pid'],
            "comm": event['comm'],
            "ctx": event.get('context', 'UNKNOWN'),
            "type": "NET" if is_net else "EXEC",
            "count": 1
        }
        
        if is_net:
            clean_event["dst"] = f"{event.get('dst_ip')}:{event.get('dport')}"

        if current_cluster and \
           current_cluster['comm'] == clean_event['comm'] and \
           current_cluster['ctx'] == clean_event['ctx'] and \
           current_cluster['type'] == clean_event['type']:
            
            current_cluster['count'] += 1
            current_cluster['t'] = clean_event['t'] 
        else:
            if current_cluster:
                compressed_timeline.append(current_cluster)
            current_cluster = clean_event

    if current_cluster:
        compressed_timeline.append(current_cluster)

    return compressed_timeline

# --- 2. MULTI-LLM STRATEGY PATTERN ---

SYSTEM_PROMPT = """
You are an elite Linux Kernel Forensic Analyst. Analyze this eBPF flight recorder timeline (T=0 is the dump trigger).

CRITICAL CONTEXT:
1. If the final events are 'sudo' and 'kill', the dump was MANUALLY TRIGGERED via CLI. State Root Cause as "Manual Diagnostic Trigger".
2. If the final event is a network connection to port 8080 (often by a python3 or curl process), the dump was TRIGGERED OVER THE NETWORK. State Root Cause as "Remote Diagnostic Trigger".
3. Look for Resource Exhaustion: A high 'count' of rapid executions indicates a fork bomb or rogue loop.

RETURN ONLY VALID JSON. SCHEMA:
{
    "root_cause": "Specific, factual summary.",
    "confidence": "high|medium|low",
    "evidence": ["Fact 1", "Fact 2"],
    "remediation": "Actionable engineering advice."
}
"""

def extract_json(raw_text):
    """Helper to strip markdown formatting from LLM responses."""
    try:
        clean = raw_text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse LLM output as JSON. Raw output:\n{raw_text}")
        return None

class LLMProvider(ABC):
    @abstractmethod
    def analyze(self, timeline_json: str) -> dict:
        pass

class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

    def analyze(self, timeline_json: str) -> dict:
        payload = {"contents": [{"parts": [{"text": f"{SYSTEM_PROMPT}\n\nTIMELINE:\n{timeline_json}"}]}]}
        res = requests.post(f"{self.url}?key={self.api_key}", json=payload)
        res.raise_for_status()
        return extract_json(res.json()['candidates'][0]['content']['parts'][0]['text'])

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4-turbo"):
        self.api_key = api_key
        self.model = model
        self.url = "https://api.openai.com/v1/chat/completions"

    def analyze(self, timeline_json: str) -> dict:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "response_format": { "type": "json_object" },
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": timeline_json}
            ]
        }
        res = requests.post(self.url, json=payload, headers=headers)
        res.raise_for_status()
        return extract_json(res.json()['choices'][0]['message']['content'])

class ClaudeProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307"):
        self.api_key = api_key
        self.model = model
        self.url = "https://api.anthropic.com/v1/messages"

    def analyze(self, timeline_json: str) -> dict:
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        payload = {
            "model": self.model,
            "max_tokens": 1000,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": timeline_json}]
        }
        res = requests.post(self.url, json=payload, headers=headers)
        res.raise_for_status()
        return extract_json(res.json()['content'][0]['text'])

class LocalProvider(LLMProvider):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3"):
        self.url = f"{base_url}/api/generate"
        self.model = model

    def analyze(self, timeline_json: str) -> dict:
        payload = {
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": timeline_json,
            "stream": False,
            "format": "json"
        }
        res = requests.post(self.url, json=payload)
        res.raise_for_status()
        return extract_json(res.json()['response'])

class LLMFactory:
    @staticmethod
    def get_provider():
        provider_name = os.getenv("LLM_PROVIDER", "").lower()
        api_key = os.getenv("LLM_API_KEY", "")

        if provider_name == "openai":
            if not api_key: raise ValueError("LLM_API_KEY required for OpenAI.")
            return OpenAIProvider(api_key, os.getenv("LLM_MODEL", "gpt-4-turbo"))
        
        elif provider_name == "claude":
            if not api_key: raise ValueError("LLM_API_KEY required for Claude.")
            return ClaudeProvider(api_key, os.getenv("LLM_MODEL", "claude-3-haiku-20240307"))
        
        elif provider_name == "local":
            return LocalProvider(os.getenv("LLM_BASE_URL", "http://localhost:11434"), os.getenv("LLM_MODEL", "llama3"))
        
        elif provider_name == "gemini":
             if not api_key: raise ValueError("LLM_API_KEY required for Gemini.")
             return GeminiProvider(api_key)
             
        # Fallback to legacy behavior if only LLM_API_KEY is set (assume Gemini)
        elif api_key:
            return GeminiProvider(api_key)
            
        return None # No LLM configured

# --- MAIN ---
def analyze_incident(filename):
    try:
        with open(filename, 'r') as f: raw_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: File '{filename}' not found.")
        return

    timeline = contextualize(raw_data)
    print(f"[*] Compression ratio: {len(raw_data)} raw events -> {len(timeline)} distinct clusters.\n")

    # 1. Always print the deterministic timeline
    print("=== ⏱️  FLIGHT RECORDER TIMELINE ===")
    for event in timeline[-15:]: # Print the last 15 events leading to the crash
        print(f"[{event['t']}] PID:{event['pid']} | CTX:{event['ctx']} | COMM:{event['comm']} | " + 
              (f"SYS_EXEC (x{event['count']})" if event['type'] == 'EXEC' else f"TCP_CONN -> {event['dst']}"))

    # 2. Attempt AI Analysis if configured
    try:
        ai_engine = LLMFactory.get_provider()
    except Exception as e:
        print(f"\n[!] AI Configuration Error: {e}")
        return

    if not ai_engine:
        print("\n[ℹ️] AI Analysis skipped. Set LLM_PROVIDER and LLM_API_KEY to enable the Virtual SRE.")
        return

    print(f"\n--- Contacting Virtual SRE ({ai_engine.__class__.__name__}) ---")
    
    try:
        report = ai_engine.analyze(json.dumps(timeline))
        if report:
            print("\n=== 🕵️  VIRTUAL SRE REPORT ===")
            print(f"🔴 ROOT CAUSE:  {report.get('root_cause')}")
            print(f"⚖️  CONFIDENCE:  {report.get('confidence')}")
            print("\n🔍 EVIDENCE:")
            for ev in report.get('evidence', []):
                print(f"   - {ev}")
            print(f"\n🛡️  REMEDIATION: {report.get('remediation')}")
    except Exception as e:
        print(f"\n[!] AI Analysis failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2: 
        print("Usage: python3 analyze_real.py <incident.json>")
    else: 
        analyze_incident(sys.argv[1])