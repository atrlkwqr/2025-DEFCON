import os
import time
import threading
from flask import Flask, jsonify, send_from_directory

app = Flask(__name__)

# pcap 파일을 저장하고 감시할 디렉터리
PCAP_DIR = "mock_pcap_storage"
os.makedirs(PCAP_DIR, exist_ok=True)

# API가 제공할 패킷 목록 (메모리에 저장)
FOUND_PACKETS = []
# 이미 API에 추가된 파일명을 추적하기 위한 집합
SEEN_FILES = set()
lock = threading.Lock()

def watch_pcap_directory():
    """mock_pcap_storage 디렉터리를 감시하여 새로 추가된 pcap 파일을 FOUND_PACKETS에 추가합니다."""
    while True:
        try:
            with lock:
                # 디렉터리 내의 모든 .pcap 파일을 스캔
                for fname in os.listdir(PCAP_DIR):
                    if fname.endswith(".pcap") and fname not in SEEN_FILES:
                        # 클라이언트가 다운로드할 URL 경로 생성
                        url_path = f"/pcaps/{fname}"
                        FOUND_PACKETS.append({"url": url_path})
                        SEEN_FILES.add(fname)
                        print(f"[+] 새로운 pcap 파일 감지: {fname}, API 목록에 추가됨")
        except Exception as e:
            print(f"[!] 디렉터리 감시 중 오류 발생: {e}")
        
        # 1초마다 디렉터리를 다시 스캔
        time.sleep(1)

@app.route('/api/packets/', methods=['POST'])
def get_packets():
    """감지된 pcap 목록을 반환하는 API 엔드포인트입니다."""
    with lock:
        return jsonify({"packets": FOUND_PACKETS})

@app.route('/pcaps/<path:filename>')
def download_pcap(filename):
    """pcap 파일을 다운로드할 수 있도록 제공합니다."""
    print(f"[*] pcap 다운로드 요청 수신: {filename}")
    return send_from_directory(PCAP_DIR, filename)

if __name__ == "__main__":
    # 백그라운드에서 pcap 디렉터리 감시 스레드 시작
    pcap_watcher_thread = threading.Thread(target=watch_pcap_directory, daemon=True)
    pcap_watcher_thread.start()

    # Flask 서버 시작
    print("가상 API 서버가 http://127.0.0.1:8088 에서 실행 중입니다.")
    print(f"pcap 파일을 '{PCAP_DIR}' 디렉터리에 추가하세요.")
    app.run(host='127.0.0.1', port=8088)