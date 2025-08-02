import os
import sys
import dpkt
import socket
import base64
import base58
import urllib.parse
from termcolor import cprint, colored
from pathlib import Path

def rot13(s):
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    ))

def all_encodings(keyword: str) -> dict:
    encoded = {}
    try:
        encoded['plain'] = keyword
        encoded['lower'] = keyword.lower()
        encoded['upper'] = keyword.upper()
        encoded['capitalized'] = keyword.capitalize()
        encoded['base64'] = base64.b64encode(keyword.encode()).decode()
        encoded['base32'] = base64.b32encode(keyword.encode()).decode()
        encoded['base58'] = base58.b58encode(keyword.encode()).decode()
        encoded['hex'] = keyword.encode().hex()
        encoded['rot13'] = rot13(keyword)
        encoded['url'] = urllib.parse.quote(keyword)
        encoded['utf16le'] = ''.join(f"{c}\x00" for c in keyword).encode().hex()
    except Exception:
        pass
    return encoded

KEYWORD_FILE = "keyword.txt"

# ===== 키워드 파일 체크 =====
if not os.path.exists(KEYWORD_FILE):
    print(f"[!] {KEYWORD_FILE} 파일이 존재하지 않습니다.")
    sys.exit(1)

# ===== 키워드 로딩 및 인코딩 사전 구축 =====
with open(KEYWORD_FILE, 'r', encoding='utf-8') as f:
    KEYWORDS = [line.strip() for line in f if line.strip()]

if not KEYWORDS:
    print("[!] keyword.txt에 키워드가 없습니다.")
    sys.exit(1)

ENCODED_KEYWORDS = {}  # {encoded_value_lower: (original_keyword, encoding_type)}
for kw in KEYWORDS:
    enc_dict = all_encodings(kw)
    for method, val in enc_dict.items():
        if val:
            ENCODED_KEYWORDS[val.lower()] = (kw, method)

# ===== 모든 스트림 폴더 반복 =====
streams_base = "streams"
exploit_base = "exploits"

for folder_name in sorted(os.listdir(streams_base)):
    if not folder_name.startswith("streams_"):
        continue

    STREAM_DIR = os.path.join(streams_base, folder_name)
    EXPLOIT_DIR = os.path.join(exploit_base, folder_name.replace("streams_", "exploits_"))

    if not os.path.isdir(STREAM_DIR):
        continue

    cprint(f"\n[>] 폴더 분석 시작: {STREAM_DIR}", "blue")

    for fname in os.listdir(STREAM_DIR):
        if not fname.endswith(".pcap"):
            continue

        fpath = os.path.abspath(os.path.join(STREAM_DIR, fname))
        match_results = set()

        try:
            with open(fpath, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for _, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not isinstance(ip, dpkt.ip.IP): continue
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP): continue
                    if not tcp.data: continue

                    try:
                        decoded = tcp.data.decode(errors='ignore').lower()
                        for encoded_val, (orig, method) in ENCODED_KEYWORDS.items():
                            if encoded_val in decoded:
                                match_results.add((orig, method))
                    except Exception:
                        continue

            # ===== 결과 출력 =====
            if match_results:
                exploit_path = os.path.abspath(
                    os.path.join(EXPLOIT_DIR, fname.replace(".pcap", ".py"))
                )

                cprint(f"[MATCH] PCAP: {fpath}", "green")
                if os.path.exists(exploit_path):
                    cprint(f"        └── Exploit: {exploit_path}", "cyan")
                else:
                    cprint(f"        └── Exploit: [NOT FOUND]", "red")

                for kw, method in sorted(match_results):
                    cprint(f"        └── Matched: {colored(kw, 'yellow')} → {colored(method, 'magenta')}", "white")

        except Exception as e:
            cprint(f"[!] Failed to process {fname}: {e}", "red")

