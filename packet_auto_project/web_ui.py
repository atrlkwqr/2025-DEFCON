

from flask import Flask, request, render_template, send_from_directory, redirect, url_for
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

app = Flask(__name__)

REQUIRED_DIRS = ["templates", "targets", "streams", "exploits", "utils"]
for d in REQUIRED_DIRS:
    os.makedirs(d, exist_ok=True)

KEYWORD_FILE = "keyword.txt"
UPLOAD_DIR = "targets"
STREAM_DIR_BASE = "streams"
EXPLOIT_DIR_BASE = "exploits"
API_URL = "https://stella.qwerty.or.kr:8080/api/packets/"
DOWNLOAD_BASE = "https://stella.qwerty.or.kr:8080"
TEAM_TOKEN = "7a14236938cf2579324c458c639d07f224d08a6ea38be5017728969be1507b70"

def extract_streams(pcap_path, stream_dir, tag):
    cmd = f"tcpdump -nn -r {pcap_path} tcp"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    keys = set()

    for line in proc.stdout:
        if 'IP ' not in line:
            continue
        try:
            parts = line.strip().split()
            ip_idx = parts.index('IP')
            src = parts[ip_idx + 1].rsplit('.', 1)
            dst = parts[ip_idx + 3].rstrip(':').rsplit('.', 1)
            src_ip, src_port = src[0], src[1]
            dst_ip, dst_port = dst[0], dst[1]

            if (src_ip, src_port) < (dst_ip, dst_port):
                key = f"{src_ip}_{src_port}__{dst_ip}_{dst_port}"
            else:
                key = f"{dst_ip}_{dst_port}__{src_ip}_{src_port}"
            keys.add(key)
        except Exception:
            continue

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
        except Exception as e:
            print(f"[!] Failed to extract stream {key}: {e}")

def generate_exploit(pcap_file, exploit_dir):
    CIP, CPORT, SIP, SPORT = None, None, None, None
    chunks = []
    cur_dir, buf = None, b''

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Failed to read pcap: {pcap_file}: {e}")
        return

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        tcp = pkt[TCP]
        ip = pkt[IP]
        if not tcp.payload:
            continue

        src = (ip.src, tcp.sport)
        dst = (ip.dst, tcp.dport)

        if CIP is None:
            CIP, CPORT = src
            SIP, SPORT = dst

        direction = "C2S" if src == (CIP, CPORT) else "S2C"
        if cur_dir != direction:
            if buf:
                chunks.append((cur_dir, buf))
                buf = b''
            cur_dir = direction
        buf += bytes(tcp.payload)

    if buf:
        chunks.append((cur_dir, buf))

    if not chunks:
        print(f"[!] No valid TCP data in {pcap_file}")
        return

    fname = os.path.basename(pcap_file).replace(".pcap", ".py")
    out_path = os.path.join(exploit_dir, fname)

    with open(out_path, 'w') as f:
        f.write("from pwn import *\n")
        f.write("context.log_level = 'debug'\n\n")
        f.write(f"SIP = \"{SIP}\"\nSPORT = {SPORT}\n\n")
        f.write("p = remote(SIP, SPORT)\n\n")
        for i, (d, b) in enumerate(chunks, 1):
            if d == 'C2S':
                f.write(f"p.send(bytes.fromhex(\"{b.hex()}\"))\n\n")
            else:
                f.write(f"data = p.recvn({len(b)})\n")
                f.write(f"log.info(f\"[RECV {{len(data)}} bytes] {{data!r}}\")\n\n")
        f.write("p.interactive()\n")
    print(f"[+] Wrote exploit: {out_path}")

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
        if not stream_pcap.endswith(".pcap"):
            continue
        fullpath = os.path.join(stream_dir, stream_pcap)
        generate_exploit(fullpath, exploit_dir)
    
    return exploit_dir


app = Flask(__name__)

REQUIRED_DIRS = ["templates", "targets", "streams", "exploits", "utils"]
for d in REQUIRED_DIRS:
    os.makedirs(d, exist_ok=True)

KEYWORD_FILE = "keyword.txt"
UPLOAD_DIR = "targets"
API_URL = "https://stella.qwerty.or.kr:8080/api/packets/"
DOWNLOAD_BASE = "https://stella.qwerty.or.kr:8080"
TEAM_TOKEN = "7a14236938cf2579324c458c639d07f224d08a6ea38be5017728969be1507b70"

def fetch_packets_loop():
    seen_files = set(os.listdir(UPLOAD_DIR))
    while True:
        try:
            # First, process any unprocessed pcaps that might exist from previous runs
            all_pcaps_in_targets = [f for f in os.listdir(UPLOAD_DIR) if f.endswith('.pcap')]
            existing_stream_dirs = os.listdir(STREAM_DIR_BASE)

            for pcap_file in all_pcaps_in_targets:
                pcap_base_name = pcap_file.replace('.pcap', '')
                is_processed = any(d.startswith(pcap_base_name) for d in existing_stream_dirs)
                if not is_processed:
                    print(f"[*] Found unprocessed pcap: {pcap_file}. Starting analysis...")
                    analyze_pcap(os.path.join(UPLOAD_DIR, pcap_file))
                    print(f"[+] Analysis finished for {pcap_file}.")
            
            # Then, check for new pcaps from the server
            resp = requests.post(API_URL, data={"team_token": TEAM_TOKEN}, timeout=10, verify=False)
            packets = resp.json().get("packets", [])
            for entry in packets:
                url = entry["url"]
                fname = os.path.basename(url)
                out_path = os.path.join(UPLOAD_DIR, fname)
                if fname in seen_files:
                    continue
                full_url = urljoin(DOWNLOAD_BASE, url)
                r = requests.get(full_url, timeout=15, verify=False)
                if r.status_code == 200:
                    with open(out_path, "wb") as f:
                        f.write(r.content)
                    seen_files.add(fname)
                    # Automatically analyze the new pcap
                    print(f"[*] New pcap detected: {fname}. Starting analysis...")
                    analyze_pcap(out_path)
                    print(f"[+] Analysis finished for {fname}.")
        except Exception as e:
            print(f"[!] Auto-fetch error: {e}")
        time.sleep(300) # 5 minutes

t = threading.Thread(target=fetch_packets_loop, daemon=True)
t.start()

def run_keyword_search(exploit_dir=None, specific_keywords=None):
    results = []

    if specific_keywords:
        raw_keywords = specific_keywords
    else:
        raw_keywords = []
        if os.path.exists(KEYWORD_FILE):
            with open(KEYWORD_FILE, "r", encoding="utf-8") as f:
                raw_keywords = [line.strip() for line in f if line.strip()]

    if not raw_keywords:
        return []

    # Prepare keywords
    plain_keywords = []
    regex_keywords = []
    for kw in raw_keywords:
        if kw.startswith("regex:"):
            try:
                pattern = kw[6:]
                regex_keywords.append({
                    "keyword": kw,
                    "pattern": re.compile(pattern, re.IGNORECASE)
                })
            except re.error as e:
                print(f"[!] Invalid regex '{kw}': {e}")
        elif len(kw) > 2:
            plain_keywords.append({"keyword": kw, "plain": kw.lower()})

    search_path = exploit_dir if exploit_dir else "exploits"

    for root, _, files in os.walk(search_path):
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            
            py_path = os.path.join(root, fname)
            try:
                with open(py_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                
                file_matches = []
                seen_matches = set()

                for i, line in enumerate(lines):
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue

                    # --- Search Logic ---
                    # 1. Regex Search (on original line)
                    for item in regex_keywords:
                        for match in item["pattern"].finditer(line):
                            match_tuple = (item["keyword"], i)
                            if match_tuple not in seen_matches:
                                file_matches.append({"keyword": item["keyword"], "type": "regex", "line": line_stripped})
                                seen_matches.add(match_tuple)

                    # 2. Plain Search (case-insensitive)
                    for item in plain_keywords:
                        if item["plain"] in line.lower():
                            match_tuple = (item["keyword"], "plain", i)
                            if match_tuple not in seen_matches:
                                file_matches.append({"keyword": item["keyword"], "type": "plain", "line": line_stripped})
                                seen_matches.add(match_tuple)

                    # 3. Hex Search (decode then search)
                    for hex_match in re.finditer(r'([0-9a-fA-F]{6,})', line):
                        try:
                            decoded_str = bytes.fromhex(hex_match.group(1)).decode('utf-8', errors='ignore').lower()
                            for item in plain_keywords:
                                if item["plain"] in decoded_str:
                                    match_tuple = (item["keyword"], "hex", i)
                                    if match_tuple not in seen_matches:
                                        file_matches.append({"keyword": item["keyword"], "type": "hex", "line": line_stripped})
                                        seen_matches.add(match_tuple)
                        except ValueError:
                            continue

                    # 4. Base64 Search (decode then search)
                    for b64_match in re.finditer(r'([A-Za-z0-9+/=]{8,})', line):
                        try:
                            # Add padding if needed
                            b64_str = b64_match.group(1)
                            rem = len(b64_str) % 4
                            if rem > 0:
                                b64_str += "=" * (4 - rem)
                            decoded_str = base64.b64decode(b64_str).decode('utf-8', errors='ignore').lower()
                            for item in plain_keywords:
                                if item["plain"] in decoded_str:
                                    match_tuple = (item["keyword"], "base64", i)
                                    if match_tuple not in seen_matches:
                                        file_matches.append({"keyword": item["keyword"], "type": "base64", "line": line_stripped})
                                        seen_matches.add(match_tuple)
                        except (ValueError, binascii.Error):
                            continue

                if file_matches:
                    tag = os.path.basename(root)
                    pcap_name = fname.replace(".py", ".pcap")
                    pcap_path = os.path.join("streams", tag.replace("exploits_", "streams_"), pcap_name)
                    results.append({
                        "pcap": pcap_path,
                        "exploit": py_path,
                        "matches": file_matches
                    })
            except Exception as e:
                print(f"[!] Keyword search error on file {py_path}: {e}")
    return results

@app.route("/")
def index():
    return redirect(url_for("main_page"))


@app.route("/main", methods=["GET", "POST"])
def main_page():
    results = []
    selected_file = None
    if request.method == "POST":
        selected_file = request.form.get("pcap_select")
        if not selected_file:
            return "파일을 선택하세요.", 400

        if selected_file == "__ALL__":
            pcap_files_to_process = [f for f in os.listdir(UPLOAD_DIR) if f.endswith(".pcap")]
            for fname in pcap_files_to_process:
                save_path = os.path.join(UPLOAD_DIR, fname)
                analyze_pcap(save_path)
            results = run_keyword_search()
        else:
            save_path = os.path.join(UPLOAD_DIR, selected_file)
            exploit_dir_name = analyze_pcap(save_path)
            results = run_keyword_search(exploit_dir=exploit_dir_name)

    for r in results:
        r['exploit_abs_path'] = os.path.abspath(r['exploit'])

    pcap_files = sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith(".pcap")])
    keywords = []
    if os.path.exists(KEYWORD_FILE):
        with open(KEYWORD_FILE, "r", encoding="utf-8") as f:
            keywords = [line.strip() for line in f if line.strip()]
    processed_pcap_dirs = sorted(os.listdir("streams"))

    return render_template("index.html", 
                           pcap_files=pcap_files, 
                           results=results, 
                           selected_file=selected_file, 
                           keywords=keywords, 
                           processed_pcap_dirs=processed_pcap_dirs)


@app.route("/pcap/<dir_name>")
def pcap_details(dir_name):
    stream_dir_path = os.path.join("streams", dir_name)
    exploit_dir_path = os.path.join("exploits", dir_name)

    if not os.path.isdir(stream_dir_path) or not os.path.isdir(exploit_dir_path):
        return "Pcap data not found.", 404

    stream_files = os.listdir(stream_dir_path)
    exploit_files = os.listdir(exploit_dir_path)

    keyword_results = run_keyword_search(exploit_dir=exploit_dir_path)
    for r in keyword_results:
        r['exploit_abs_path'] = os.path.abspath(r['exploit'])

    return render_template("pcap_details.html", pcap_name=dir_name, stream_files=stream_files, exploit_files=exploit_files, stream_dir=dir_name, exploit_dir=dir_name, keyword_results=keyword_results)


@app.route("/add_keyword", methods=["POST"])
def add_keyword():
    new_word = request.form.get("new_keyword", "").strip()
    if new_word:
        with open(KEYWORD_FILE, "a", encoding="utf-8") as f:
            f.write(f"{new_word}\n")

    # 1. Analyze any unprocessed pcaps
    all_pcaps_in_targets = [f for f in os.listdir(UPLOAD_DIR) if f.endswith('.pcap')]
    existing_stream_dirs = os.listdir(STREAM_DIR_BASE)

    for pcap_file in all_pcaps_in_targets:
        pcap_base_name = pcap_file.replace('.pcap', '')
        is_processed = any(d.startswith(pcap_base_name) for d in existing_stream_dirs)
        if not is_processed:
            print(f"[*] Found unprocessed pcap on keyword add: {pcap_file}. Analyzing...")
            analyze_pcap(os.path.join(UPLOAD_DIR, pcap_file))
            print(f"[+] Analysis finished for {pcap_file}.")

    # 2. After adding a new keyword, re-run the search for the new keyword only
    results = run_keyword_search(specific_keywords=[new_word])
    for r in results:
        r['exploit_abs_path'] = os.path.abspath(r['exploit'])

    # 3. Gather context and render the main page template directly
    pcap_files = sorted([f for f in os.listdir(UPLOAD_DIR) if f.endswith(".pcap")])
    keywords = []
    if os.path.exists(KEYWORD_FILE):
        with open(KEYWORD_FILE, "r", encoding="utf-8") as f:
            keywords = [line.strip() for line in f if line.strip()]
    processed_pcap_dirs = sorted(os.listdir("streams"))

    return render_template("index.html", 
                           pcap_files=pcap_files, 
                           results=results, 
                           selected_file=None, 
                           keywords=keywords, 
                           processed_pcap_dirs=processed_pcap_dirs)


@app.route("/delete_keyword", methods=["POST"])
def delete_keyword():
    del_word = request.form.get("del_keyword", "").strip()
    if del_word and os.path.exists(KEYWORD_FILE):
        with open(KEYWORD_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() != del_word]
        with open(KEYWORD_FILE, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")
    return redirect(url_for("index"))


@app.route("/download/<path:filename>")
def download_file(filename):
    base = filename.split("/")[0]
    return send_from_directory(base, "/".join(filename.split("/")[1:]))


if __name__ == "__main__":
    app.run(debug=True)

