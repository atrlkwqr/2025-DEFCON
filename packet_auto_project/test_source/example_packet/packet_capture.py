#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

def save_tcp_flows_to_files(pcap_file, output_dir='./output'):
    """
    PCAP 파일에서 TCP 플로우를 추출하여, 각 플로우의 송수신 데이터를
    지정된 디렉터리에 파일로 저장합니다.

    Args:
        pcap_file (str): 분석할 PCAP 파일 경로
        output_dir (str): 결과를 저장할 디렉터리 경로
    """
    # 1. 출력 디렉터리 설정 (기존 디렉터리 삭제 후 새로 생성)
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        print(f"🗑️  기존 '{output_dir}' 디렉터리를 삭제했습니다.")
    os.makedirs(output_dir)
    print(f"✨ '{output_dir}' 디렉터리를 새로 생성했습니다.")

    # 2. PCAP 파일 읽기
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"❌ 오류: 파일을 찾을 수 없습니다 - {pcap_file}")
        return
    except Exception as e:
        print(f"❌ 오류: PCAP 파일을 읽는 중 문제가 발생했습니다 - {e}")
        return

    # 3. TCP 플로우 데이터 추출 (이전 코드와 동일)
    flows = defaultdict(lambda: {'client': None, 'sequence': []})
    print(f"🔍 총 {len(packets)}개의 패킷을 분석합니다...")

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        if not tcp_layer.payload:
            continue

        src_ip, dst_ip = sorted((ip_layer.src, ip_layer.dst))
        src_port, dst_port = sorted((tcp_layer.sport, tcp_layer.dport))
        flow_key = (src_ip, src_port, dst_ip, dst_port)
        
        if src_port == 1234:
            challenge = "chall1"
        elif src_port == 2345:
            challenge = "chall2"

        current_flow = flows[flow_key]

        if current_flow['client'] is None:
            current_flow['client'] = (ip_layer.src, tcp_layer.sport)

        payload_bytes = bytes(tcp_layer.payload)
        if (ip_layer.src, tcp_layer.sport) == current_flow['client']:
            current_flow['sequence'].append(('sent', payload_bytes))
        else:
            current_flow['sequence'].append(('recv', payload_bytes))

    # 4. 추출된 데이터를 파일로 저장
    flow_id = 0
    for data in flows.values():
        if not data['sequence']:
            continue
        
        flow_id += 1
        file_content = b''
        file_content = b'''
from pwn import *

p = remote("10.12.0.1", 1234)
        \n'''
        # 요청한 b'send("""...""")\n' 또는 b'recv("""...""")\n' 형태로 바이트 문자열 생성
        for direction, payload in data['sequence']:
            if direction == 'sent':
                file_content += b'p.recv("""' + payload.replace(b"\n", b"") + b'""")\n'
            else:
                file_content += b'p.send("""' + payload.replace(b"\n", b"") + b'""")\n'

        # 파일 저장
        file_content += b"\np.close()\n"
        file_path = os.path.join(output_dir, f"{flow_id}.txt")
        try:
            with open(file_path, 'wb') as f:
                f.write(file_content)
        except IOError as e:
            print(f"❌ 오류: '{file_path}' 파일 저장 중 문제가 발생했습니다 - {e}")

    print(f"\n✅ 총 {flow_id}개의 유효한 플로우를 '{output_dir}' 디렉터리에 저장했습니다.")


if __name__ == '__main__':
    # 여기에 분석하고 싶은 pcap 파일 경로를 입력하세요.
    # pcap_file_path = 'team4.1723246071.a81d70c7e1bc1c9c724398ba9d172c04.pcap'
    pcap_file_path = 'team4.1723335304.af4ed1f7df5ed99828d761c60532bb76.pcap'
    save_tcp_flows_to_files(pcap_file_path)

