#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

API_KEY=""
SERVER_URL=""
ACCESS_LOG="${LOGGUARD_ACCESS_LOG:-/var/log/nginx/access.log}"
AGENT_DIR="${LOGGUARD_AGENT_DIR:-/opt/logguard-agent}"
ENV_FILE="/etc/logguard/logguard-agent.env"
SERVICE_FILE="/etc/systemd/system/logguard-agent.service"
PYTHON_FILE="$AGENT_DIR/agent.py"
MAX_BATCH_SIZE=90

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)
            API_KEY="${2:-}"
            shift 2
            ;;
        --server-url)
            SERVER_URL="${2:-}"
            shift 2
            ;;
        --access-log)
            ACCESS_LOG="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$API_KEY" ]]; then
    echo -e "${RED}[ERR] API Key가 누락되었습니다. --key 값을 넣어주세요.${NC}"
    exit 1
fi

if [[ -z "$SERVER_URL" ]]; then
    echo -e "${RED}[ERR] 서버 URL이 누락되었습니다. --server-url 값을 넣어주세요.${NC}"
    exit 1
fi

SERVER_URL="${SERVER_URL%/}"
if [[ "$SERVER_URL" == http://* ]]; then
    SERVER_URL="https://${SERVER_URL#http://}"
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERR] python3가 설치되어 있지 않습니다.${NC}"
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${RED}[ERR] 이 설치 스크립트는 Linux nginx 서버 전용입니다. Mac에서는 systemd가 없어서 실행할 수 없습니다.${NC}"
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /etc/systemd/system ]]; then
    echo -e "${RED}[ERR] systemd가 없는 환경입니다. Ubuntu 같은 Linux 서버에서 실행해 주세요.${NC}"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERR] nginx 로그를 읽고 systemd 서비스를 등록하려면 root 권한이 필요합니다.${NC}"
    exit 1
fi

mkdir -p "$AGENT_DIR" /etc/logguard /var/lib/logguard

cat > "$PYTHON_FILE" <<'PY'
#!/usr/bin/env python3
import dataclasses
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import List
from pathlib import Path

LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^"]*?)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)


@dataclasses.dataclass
class State:
    offset: int = 0
    inode: int = 0


def load_state(path: Path) -> State:
    if not path.exists():
        return State()
    try:
        data = json.loads(path.read_text())
        return State(offset=int(data.get("offset", 0)), inode=int(data.get("inode", 0)))
    except Exception:
        return State()


def save_state(path: Path, state: State) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataclasses.asdict(state)))


def parse_time(value: str) -> str:
    parsed = dt.datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_line(line: str):
    match = LOG_LINE_RE.match(line.strip())
    if not match:
        return None
    try:
        return {
            "ip": match.group("ip"),
            "method": match.group("method"),
            "path": match.group("path") or "/",
            "status": int(match.group("status")),
            "userAgent": match.group("ua"),
            "timestamp": parse_time(match.group("time")),
        }
    except Exception:
        return None


class Redirect307Handler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code in (307, 308):
            newreq = urllib.request.Request(
                newurl,
                data=req.data,
                headers=req.headers,
                origin_req_host=req.origin_req_host,
                unverifiable=req.unverifiable,
                method=req.get_method()
            )
            return newreq
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def post_batch(server_url: str, api_key: str, events: List[dict]) -> bool:
    if not events:
        return True
    payload = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        f"{server_url}/api/ingest",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(Redirect307Handler)
        with opener.open(req, timeout=10) as resp:
            status = resp.status if hasattr(resp, "status") else resp.getcode()
            sys.stderr.write(f"[logguard] ingest ok: HTTP {status}\n")
            return 200 <= status < 300
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        sys.stderr.write(f"[logguard] ingest failed: HTTP {exc.code} {body}\n")
        return False
    except Exception as exc:
        sys.stderr.write(f"[logguard] ingest failed: {exc}\n")
        return False


def post_chunks(server_url: str, api_key: str, events: List[dict], chunk_size: int) -> int:
    """Send events in order, in chunks of at most chunk_size.
    Stops at the first failed chunk (never skips ahead of a failure).
    Returns how many events (from the start of the list) were confirmed sent."""
    sent = 0
    for start in range(0, len(events), chunk_size):
        chunk = events[start:start + chunk_size]
        if post_batch(server_url, api_key, chunk):
            sent += len(chunk)
        else:
            break
    return sent


def main() -> int:
    server_url = os.environ["LOGGUARD_SERVER_URL"].rstrip("/")
    api_key = os.environ["LOGGUARD_API_KEY"]
    access_log = Path(os.environ.get("LOGGUARD_ACCESS_LOG", "/var/log/nginx/access.log"))
    state_file = Path(os.environ.get("LOGGUARD_STATE_FILE", "/var/lib/logguard/state.json"))
    batch_size = int(os.environ.get("LOGGUARD_BATCH_SIZE", "20"))
    max_batch_size = int(os.environ.get("LOGGUARD_MAX_BATCH_SIZE", "90"))
    flush_interval = int(os.environ.get("LOGGUARD_FLUSH_INTERVAL", "5"))

    sys.stderr.write(f"[logguard] 에이전트 구동 시작. [{access_log}] 로그 수집을 대기 중입니다...\n")

    # Each buffer item: {"data": <event dict>, "offset": <file offset right after this line>}
    buffer: List[dict] = []
    last_flush = time.monotonic()

    while True:
        try:
            if not access_log.exists():
                sys.stderr.write(f"[logguard] access log not found: {access_log}\n")
                time.sleep(10)
                continue

            stat = access_log.stat()
            state = load_state(state_file)

            if state.inode != stat.st_ino or state.offset > stat.st_size:
                # Log rotated or truncated: any buffered-but-unsent events refer to
                # offsets in the old file and are no longer valid. Try one last
                # flush attempt before dropping them.
                if buffer:
                    events_only = [item["data"] for item in buffer]
                    sent = post_chunks(server_url, api_key, events_only, max_batch_size)
                    if sent < len(buffer):
                        sys.stderr.write(
                            f"[logguard] 로그 회전 감지: 미전송 {len(buffer) - sent}건 유실 (전송 재시도 실패)\n"
                        )
                    buffer = []
                state = State(offset=0, inode=stat.st_ino)
                save_state(state_file, state)

            with access_log.open("r", encoding="utf-8", errors="ignore") as fh:
                fh.seek(state.offset)
                while True:
                    raw_line = fh.readline()
                    if not raw_line:
                        break
                    line_end_offset = fh.tell()
                    event = parse_line(raw_line)
                    if event is not None:
                        buffer.append({"data": event, "offset": line_end_offset})
                    # NOTE: state.offset is deliberately NOT persisted here.
                    # It is only persisted below, once events are confirmed sent,
                    # so a crash/restart before a successful send re-reads and
                    # re-attempts those lines instead of silently dropping them,
                    # and never re-reads lines that were already confirmed sent.

            now = time.monotonic()
            should_flush = len(buffer) >= batch_size or (buffer and now - last_flush >= flush_interval)
            if should_flush:
                events_only = [item["data"] for item in buffer]
                sent = post_chunks(server_url, api_key, events_only, max_batch_size)
                if sent > 0:
                    state.offset = buffer[sent - 1]["offset"]
                    state.inode = stat.st_ino
                    save_state(state_file, state)
                    buffer = buffer[sent:]
                    last_flush = now
                    sys.stderr.write(f"[logguard] [SUCCESS] 전송 완료: {sent}건\n")
                if buffer:
                    sys.stderr.write(f"[logguard] {len(buffer)}건 전송 대기 중 (다음 주기에 재시도)\n")
            time.sleep(2)
        except Exception as exc:
            sys.stderr.write(f"[logguard] loop error: {exc}\n")
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
PY

chmod 700 "$PYTHON_FILE"

cat > "$ENV_FILE" <<EOF
LOGGUARD_SERVER_URL=$SERVER_URL
LOGGUARD_API_KEY=$API_KEY
LOGGUARD_ACCESS_LOG=$ACCESS_LOG
LOGGUARD_STATE_FILE=/var/lib/logguard/state.json
LOGGUARD_BATCH_SIZE=20
LOGGUARD_MAX_BATCH_SIZE=$MAX_BATCH_SIZE
LOGGUARD_FLUSH_INTERVAL=5
EOF
chmod 600 "$ENV_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=LogGuard nginx log forwarder
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/python3 -u $PYTHON_FILE
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart logguard-agent
systemctl enable logguard-agent

echo -e "${GREEN}[SUCCESS] LogGuard nginx log forwarder 설치가 완료되었습니다.${NC}"
echo -e "${GREEN}[SUCCESS] 수집 대상 로그: $ACCESS_LOG${NC}"
echo -e "${GREEN}[SUCCESS] 전송 서버: $SERVER_URL${NC}"
echo -e "${YELLOW}[WARN] nginx access log 형식이 기본 combined가 아니면 파서 수정이 필요할 수 있습니다.${NC}"
