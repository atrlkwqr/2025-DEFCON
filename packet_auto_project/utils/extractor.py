import os
import subprocess
from scapy.all import rdpcap, TCP, IP

def extract_and_generate(pcap_path, tag):
    stream_dir = f"streams/streams_{tag}"
    exploit_dir = f"exploits/exploits_{tag}"
    os.makedirs(stream_dir, exist_ok=True)
    os.makedirs(exploit_dir, exist_ok=True)

    # === stream 추출 ===
    cmd = f"tcpdump -nn -r '{pcap_path}' tcp"
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

            # === exploit 생성 ===
            generate_exploit(out_file, exploit_dir)
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
                # Add original data as a comment for analysis
                try:
                    comment = b.decode('utf-8', errors='ignore').replace('"', '"')
                    f.write(f'# C2S Data: """{comment}"""\n')
                except Exception:
                    pass
                f.write(f"p.send(bytes.fromhex(\"{b.hex()}\"))\n\n")
            else:
                # Add original data as a comment for analysis
                try:
                    comment = b.decode('utf-8', errors='ignore').replace('"', '"')
                    f.write(f'# S2C Data: """{comment}"""\n')
                except Exception:
                    pass
                f.write(f"data = p.recvn({len(b)})\n")
                f.write(f"log.info(f\"[RECV {{len(data)}} bytes] {{data!r}}\")\n\n")
        f.write("p.interactive()\n")
    print(f"[+] Wrote exploit: {out_path}")

