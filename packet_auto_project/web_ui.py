

from flask import Flask, request, render_template, send_from_directory, redirect, url_for, Response
import os
import datetime
import threading
import time
import requests
from urllib.parse import urljoin
import base64
import binascii
import re
import subprocess
from scapy.all import rdpcap, TCP, IP
import queue

# --- SSE Message Announcer (Pub/Sub Model) ---
class MessageAnnouncer:
    def __init__(self):
        self.listeners = []

    def listen(self):
        q = queue.Queue(maxsize=5)
        self.listeners.append(q)
        return q

    def remove_listener(self, q):
        if q in self.listeners:
            self.listeners.remove(q)

    def announce(self, msg):
        for i in reversed(range(len(self.listeners))):
            try:
                self.listeners[i].put_nowait(msg)
            except queue.Full:
                del self.listeners[i]

# --- Global Instances and App Config ---
announcer = MessageAnnouncer()
app = Flask(__name__)

# Directories and Files
REQUIRED_DIRS = ["templates", "targets", "streams", "exploits", "utils"]
for d in REQUIRED_DIRS:
    os.makedirs(d, exist_ok=True)

KEYWORD_FILE = "keyword.txt"
UPLOAD_DIR = "targets"
STREAM_DIR_BASE = "streams"
EXPLOIT_DIR_BASE = "exploits"

# API Config
API_URL = "http://127.0.0.1:8088/api/packets/"
DOWNLOAD_BASE = "http://127.0.0.1:8088"
TEAM_TOKEN = "7a14236938cf2579324c458c639d07f224d08a6ea38be5017728969be1507b70"


# --- Core Pcap Analysis Functions ---
def extract_streams(pcap_path, stream_dir, tag):
    cmd = f"tcpdump -nn -r {pcap_path} tcp"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    keys = set()
    for line in proc.stdout:
        if 'IP ' not in line: continue
        try:
            parts = line.strip().split()
            ip_idx = parts.index('IP')
            src = parts[ip_idx + 1].rsplit('.', 1)
            dst = parts[ip_idx + 3].rstrip(':').rsplit('.', 1)
            key = f"{src[0]}_{src[1]}__{dst[0]}_{dst[1]}" if (src[0], src[1]) < (dst[0], dst[1]) else f"{dst[0]}_{dst[1]}__{src[0]}_{src[1]}"
            keys.add(key)
        except Exception: continue
    for key in keys:
        try:
            src, dst = key.split('__')
            src_ip, src_port = src.rsplit('_', 1)
            dst_ip, dst_port = dst.rsplit('_', 1)
            base_name = f"{tag}__{key}.pcap"
            out_file = os.path.join(stream_dir, base_name)
            i = 1
            while os.path.exists(out_file):
                out_file = os.path.join(stream_dir, base_name.replace(".pcap", f"_{i}.pcap"))
                i += 1
            tcpdump_cmd = (
                f"tcpdump -r '{pcap_path}' -nn -w '{out_file}' "
                f"\"tcp and ((src host {src_ip} and src port {src_port} and dst host {dst_ip} and dst port {dst_port}) or "
                f"(src host {dst_ip} and src port {dst_port} and dst host {src_ip} and dst port {src_port}))\""
            )
            subprocess.run(tcpdump_cmd, shell=True, stderr=subprocess.DEVNULL)
        except Exception as e: print(f"[!] Stream extraction failed {key}: {e}")

def generate_exploit(pcap_file, exploit_dir):
    CIP, CPORT, SIP, SPORT = None, None, None, None
    chunks, (cur_dir, buf) = [], (None, b'')
    try: packets = rdpcap(pcap_file)
    except Exception as e: print(f"[!] Failed to read pcap: {pcap_file}: {e}"); return
    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP) or not pkt[TCP].payload: continue
        ip, tcp = pkt[IP], pkt[TCP]
        src, dst = (ip.src, tcp.sport), (ip.dst, tcp.dport)
        if CIP is None: CIP, CPORT, SIP, SPORT = src[0], src[1], dst[0], dst[1]
        direction = "C2S" if src == (CIP, CPORT) else "S2C"
        if cur_dir != direction:
            if buf: chunks.append((cur_dir, buf))
            cur_dir, buf = direction, b''
        buf += bytes(tcp.payload)
    if buf: chunks.append((cur_dir, buf))
    if not chunks: print(f"[!] No valid TCP data in {pcap_file}"); return
    fname = os.path.basename(pcap_file).replace(".pcap", ".py")
    out_path = os.path.join(exploit_dir, fname)
    with open(out_path, 'w') as f:
        f.write("from pwn import *\ncontext.log_level = 'debug'\n\n")
        f.write(f"SIP = \"{SIP}\"\nSPORT = {SPORT}\n\np = remote(SIP, SPORT)\n\n")
        for i, (d, b) in enumerate(chunks, 1):
            if d == 'C2S': f.write(f"p.send(bytes.fromhex(\"{b.hex()}\"))\n\n")
            else: f.write(f"data = p.recvn({len(b)})\nlog.info(f\"[RECV {{len(data)}} bytes] {{data!r}}\")\n\n")
        f.write("p.interactive()\n")
    print(f"[+] Exploit written: {out_path}")

def analyze_pcap(pcap_path):
    pcap_name = os.path.basename(pcap_path)
    tag = pcap_name.replace(".pcap", "")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    stream_dir = os.path.join(STREAM_DIR_BASE, f"{tag}_{timestamp}")
    exploit_dir = os.path.join(EXPLOIT_DIR_BASE, f"{tag}_{timestamp}")
    os.makedirs(stream_dir, exist_ok=True)
    os.makedirs(exploit_dir, exist_ok=True)

    extract_streams(pcap_path, stream_dir, tag)

    for stream_pcap in os.listdir(stream_dir):
        if stream_pcap.endswith(".pcap"):
            generate_exploit(os.path.join(stream_dir, stream_pcap), exploit_dir)
    
    msg = f"분석 완료: {pcap_name}"
    announcer.announce(msg)
    return exploit_dir

# --- Background Task for Fetching Packets ---
def fetch_packets_loop():
    print("--- [FETCHER] Background thread started. --- ")
    seen_files = set(os.listdir(UPLOAD_DIR))
    while True:
        try:
            resp = requests.post(API_URL, data={"team_token": TEAM_TOKEN}, timeout=10, verify=False)
            if resp.status_code == 200:
                packets = resp.json().get("packets", [])
                for entry in packets:
                    url = entry.get("url")
                    if not url: continue
                    fname = os.path.basename(url)
                    if fname not in seen_files:
                        print(f"[*] New pcap detected: {fname}")
                        full_url = urljoin(DOWNLOAD_BASE, url)
                        r = requests.get(full_url, timeout=15, verify=False)
                        if r.status_code == 200:
                            out_path = os.path.join(UPLOAD_DIR, fname)
                            with open(out_path, "wb") as f: f.write(r.content)
                            seen_files.add(fname)
                            print(f"[+] {fname} downloaded. Starting analysis...")
                            analyze_pcap(out_path)
                        else: print(f"[!] Failed to download {fname}: {r.status_code}")
        except Exception as e: print(f"[!] Auto-fetch loop error: {e}")
        time.sleep(1)

# --- Keyword Search ---
def run_keyword_search(exploit_dir=None, specific_keywords=None):
    results = []
    raw_keywords = specific_keywords or []
    if not specific_keywords and os.path.exists(KEYWORD_FILE):
        with open(KEYWORD_FILE, "r", encoding="utf-8") as f: raw_keywords = [line.strip() for line in f if line.strip()]
    if not raw_keywords: return []
    plain_keywords, regex_keywords = [], []
    for kw in raw_keywords:
        if kw.startswith("regex:"):
            try: regex_keywords.append({"keyword": kw, "pattern": re.compile(kw[6:], re.IGNORECASE)})
            except re.error as e: print(f"[!] Invalid regex '{kw}': {e}")
        elif len(kw) > 2: plain_keywords.append({"keyword": kw, "plain": kw.lower()})
    search_path = exploit_dir or "exploits"
    for root, _, files in os.walk(search_path):
        for fname in sorted(files):
            if not fname.endswith(".py"): continue
            py_path = os.path.join(root, fname)
            try:
                with open(py_path, "r", encoding="utf-8", errors="ignore") as f: lines = f.readlines()
                file_matches, seen_matches = [], set()
                for i, line in enumerate(lines):
                    line_stripped = line.strip()
                    if not line_stripped: continue
                    for item in regex_keywords:
                        if item["pattern"].search(line): 
                            if (item["keyword"], i) not in seen_matches: file_matches.append({"keyword": item["keyword"], "type": "regex", "line": line_stripped}); seen_matches.add((item["keyword"], i))
                    for item in plain_keywords:
                        if item["plain"] in line.lower(): 
                            if (item["keyword"], "plain", i) not in seen_matches: file_matches.append({"keyword": item["keyword"], "type": "plain", "line": line_stripped}); seen_matches.add((item["keyword"], "plain", i))
                    for hex_match in re.finditer(r'([0-9a-fA-F]{6,})', line):
                        try:
                            decoded_str = bytes.fromhex(hex_match.group(1)).decode('utf-8', errors='ignore').lower()
                            for item in plain_keywords:
                                if item["plain"] in decoded_str: 
                                    if (item["keyword"], "hex", i) not in seen_matches: file_matches.append({"keyword": item["keyword"], "type": "hex", "line": line_stripped}); seen_matches.add((item["keyword"], "hex", i))
                        except ValueError: continue
                    for b64_match in re.finditer(r'([A-Za-z0-9+/=]{8,})', line):
                        try:
                            b64_str = b64_match.group(1); b64_str += "=" * (4 - len(b64_str) % 4)
                            decoded_str = base64.b64decode(b64_str).decode('utf-8', errors='ignore').lower()
                            for item in plain_keywords:
                                if item["plain"] in decoded_str: 
                                    if (item["keyword"], "base64", i) not in seen_matches: file_matches.append({"keyword": item["keyword"], "type": "base64", "line": line_stripped}); seen_matches.add((item["keyword"], "base64", i))
                        except (ValueError, binascii.Error): continue
                if file_matches:
                    tag = os.path.basename(root)
                    pcap_name = fname.replace(".py", ".pcap")
                    pcap_path = os.path.join("streams", tag, pcap_name)
                    results.append({"pcap": pcap_path, "exploit": py_path, "matches": file_matches})
            except Exception as e: print(f"[!] Keyword search error {py_path}: {e}")
    return results

# --- Flask Routes ---
@app.route("/")
def index():
    return redirect(url_for("main_page"))

@app.route("/main", methods=["GET", "POST"])
def main_page():
    results = []
    selected_file = None
    if request.method == "POST":
        selected_file = request.form.get("pcap_select")
        if not selected_file: return "Please select a file.", 400
        if selected_file == "__ALL__":
            for fname in os.listdir(UPLOAD_DIR):
                if fname.endswith(".pcap"): analyze_pcap(os.path.join(UPLOAD_DIR, fname))
            results = run_keyword_search()
        else:
            exploit_dir = analyze_pcap(os.path.join(UPLOAD_DIR, selected_file))
            results = run_keyword_search(exploit_dir=exploit_dir)
    for r in results: r['exploit_abs_path'] = os.path.abspath(r['exploit'])
    pcap_files = sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith(".pcap")])
    keywords = []
    if os.path.exists(KEYWORD_FILE): 
        with open(KEYWORD_FILE, "r", encoding="utf-8") as f: keywords = [line.strip() for line in f if line.strip()]
    processed_pcap_dirs = sorted(os.listdir("streams"))
    return render_template("index.html", pcap_files=pcap_files, results=results, selected_file=selected_file, keywords=keywords, processed_pcap_dirs=processed_pcap_dirs)

@app.route("/pcap/<dir_name>")
def pcap_details(dir_name):
    stream_dir_path = os.path.join("streams", dir_name)
    exploit_dir_path = os.path.join("exploits", dir_name)
    if not os.path.isdir(stream_dir_path) or not os.path.isdir(exploit_dir_path): return "Pcap data not found.", 404
    stream_files, exploit_files = os.listdir(stream_dir_path), os.listdir(exploit_dir_path)
    keyword_results = run_keyword_search(exploit_dir=exploit_dir_path)
    for r in keyword_results: r['exploit_abs_path'] = os.path.abspath(r['exploit'])
    return render_template("pcap_details.html", pcap_name=dir_name, stream_files=stream_files, exploit_files=exploit_files, stream_dir=dir_name, exploit_dir=dir_name, keyword_results=keyword_results)

@app.route("/add_keyword", methods=["POST"])
def add_keyword():
    new_word = request.form.get("new_keyword", "").strip()
    if new_word: 
        with open(KEYWORD_FILE, "a", encoding="utf-8") as f: f.write(f"{new_word}\n")
    return redirect(url_for("main_page"))

@app.route("/delete_keyword", methods=["POST"])
def delete_keyword():
    del_word = request.form.get("del_keyword", "").strip()
    if del_word and os.path.exists(KEYWORD_FILE):
        with open(KEYWORD_FILE, "r", encoding="utf-8") as f: lines = [line.strip() for line in f if line.strip() != del_word]
        with open(KEYWORD_FILE, "w", encoding="utf-8") as f: 
            for line in lines: f.write(f"{line}\n")
    return redirect(url_for("main_page"))

@app.route("/download/<path:filename>")
def download_file(filename):
    base, *rel_path = filename.split(os.sep)
    return send_from_directory(base, os.path.join(*rel_path))

@app.route('/stream-notifications')
def stream_notifications():
    def event_stream():
        yield "data: SSE 연결 성공. 알림 대기 중...\n\n"
        q = announcer.listen()
        try:
            while True:
                message = q.get()
                yield f"data: {message}\n\n"
        finally:
            announcer.remove_listener(q)

    response = Response(event_stream(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response

# --- Main Execution ---
if __name__ == "__main__":
    # Start the background thread for fetching packets
    fetch_thread = threading.Thread(target=fetch_packets_loop, daemon=True)
    fetch_thread.start()

    # Run the Flask app
    app.run(host="0.0.0.0", port=5000, threaded=True)
