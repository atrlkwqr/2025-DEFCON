import os

KEYWORD_FILE = "keyword.txt"
STREAM_DIR = "streams"

def run_keyword_search():
    results = []

    if not os.path.exists(KEYWORD_FILE):
        return results

    with open(KEYWORD_FILE, "r", encoding="utf-8") as f:
        keywords = [k.strip() for k in f if k.strip()]
    if not keywords:
        return results

    def rot13(s):
        return s.translate(str.maketrans(
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
        ))

    matchers = []
    for k in keywords:
        if k.startswith("url:"):
            val = k[4:]
            matchers.append((k, "url", lambda b, v=val: v.encode() in b))
        elif k.startswith("rot13:"):
            val = k[6:]
            matchers.append((k, "rot13", lambda b, v=rot13(val): v.encode() in b))
        else:
            matchers.append((k, "plain", lambda b, v=k: v.encode() in b))

    for root, dirs, files in os.walk(STREAM_DIR):
        for fname in files:
            if not fname.endswith(".pcap"):
                continue
            pcap_path = os.path.join(root, fname)
            try:
                with open(pcap_path, "rb") as f:
                    content = f.read()
                matched = []
                for kword, method, check in matchers:
                    if check(content):
                        matched.append((kword, method))
                if matched:
                    tag = os.path.basename(root)
                    exploit_name = fname.replace(".pcap", ".py")
                    exploit_path = f"exploits/exploits_{tag}/{exploit_name}"
                    results.append({
                        "pcap": pcap_path,
                        "exploit": exploit_path,
                        "matches": matched
                    })
            except Exception as e:
                print(f"[!] Failed to scan {pcap_path}: {e}")
    return results

