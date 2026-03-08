#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <keyclaw-bin>" >&2
  exit 1
fi

bin="$1"
if [ ! -x "$bin" ]; then
  echo "expected executable keyclaw binary at $bin" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for smoke-release.sh" >&2
  exit 1
fi

work="$(mktemp -d)"
home="${work}/home"
bin_dir="${work}/bin"
mkdir -p "$home"
mkdir -p "$bin_dir"
trap 'rm -rf "$work"' EXIT

cat > "${work}/send_request.py" <<'PY'
import os
import urllib.request

proxy = os.environ["HTTP_PROXY"]
url = os.environ["UPSTREAM_URL"]
data = os.environ["PAYLOAD"].encode()
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": proxy, "https": proxy})
)
req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
with opener.open(req, timeout=5):
    pass
PY

cat > "${work}/capture_upstream.py" <<'PY'
import http.server
import socketserver
import sys

body_path, port_path = sys.argv[1:3]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with open(body_path, "wb") as fh:
            fh.write(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        return

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
    with open(port_path, "w", encoding="utf-8") as fh:
        fh.write(str(server.server_address[1]))
    server.handle_request()
PY

pick_free_addr() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(f"127.0.0.1:{sock.getsockname()[1]}")
PY
}

run_doctor_smoke() {
  HOME="$home" \
  KEYCLAW_PROXY_ADDR=127.0.0.1:0 \
  KEYCLAW_PROXY_URL=http://127.0.0.1:0 \
  KEYCLAW_REQUIRE_MITM_EFFECTIVE=true \
  KEYCLAW_VAULT_PATH="${home}/doctor-vault.enc" \
  KEYCLAW_VAULT_PASSPHRASE=test-passphrase \
  "$bin" doctor >"${work}/doctor.out" 2>"${work}/doctor.err"

  grep -Fq "PASS proxy-bind" "${work}/doctor.out"
  grep -Fq "PASS ca-cert" "${work}/doctor.out"
  grep -Fq "PASS ruleset" "${work}/doctor.out"
  grep -Fq "doctor: summary:" "${work}/doctor.out"
}

run_proxy_smoke() {
  local proxy_log="${work}/proxy.err"
  local pid_path="${home}/.keyclaw/proxy.pid"

  HOME="$home" \
  KEYCLAW_PROXY_ADDR=127.0.0.1:0 \
  KEYCLAW_PROXY_URL=http://127.0.0.1:0 \
  KEYCLAW_VAULT_PATH="${home}/proxy-vault.enc" \
  KEYCLAW_VAULT_PASSPHRASE=test-passphrase \
  "$bin" proxy >"${work}/proxy.out" 2>"$proxy_log"
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "keyclaw proxy failed to detach" >&2
    cat "$proxy_log" >&2
    exit 1
  fi

  local proxy_pid=""
  for _ in $(seq 1 100); do
    if [ -s "$pid_path" ]; then
      proxy_pid="$(cat "$pid_path")"
      if kill -0 "$proxy_pid" 2>/dev/null; then
        break
      fi
    fi
    sleep 0.1
  done
  if [ -z "$proxy_pid" ] || ! kill -0 "$proxy_pid" 2>/dev/null; then
    echo "detached keyclaw proxy did not stay alive" >&2
    cat "$proxy_log" >&2
    exit 1
  fi

  kill -TERM "$proxy_pid"
  for _ in $(seq 1 100); do
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
      return
    fi
    sleep 0.1
  done

  echo "detached keyclaw proxy did not stop after SIGTERM" >&2
  cat "$proxy_log" >&2
  exit 1
}

install_fake_tool() {
  local tool="$1"
  cat > "${bin_dir}/${tool}" <<EOF
#!/usr/bin/env bash
exec python3 "${work}/send_request.py" "\$@"
EOF
  chmod +x "${bin_dir}/${tool}"
}

run_mitm_smoke() {
  local tool="$1"
  local secret="$2"
  local body_file="${work}/${tool}.body"
  local port_file="${work}/${tool}.port"

  python3 "${work}/capture_upstream.py" "$body_file" "$port_file" &
  local upstream_pid=$!
  for _ in $(seq 1 50); do
    if [ -s "$port_file" ]; then
      break
    fi
    sleep 0.1
  done
  if [ ! -s "$port_file" ]; then
    echo "upstream port file was not written for ${tool}" >&2
    exit 1
  fi

  local upstream_url
  upstream_url="http://127.0.0.1:$(cat "$port_file")"
  local proxy_addr
  proxy_addr="$(pick_free_addr)"
  local payload
  payload="$(printf '{"prompt":"api_key = %s"}' "$secret")"
  install_fake_tool "$tool"

  HOME="$home" \
  PATH="${bin_dir}:${PATH}" \
  KEYCLAW_PROXY_ADDR="$proxy_addr" \
  KEYCLAW_PROXY_URL="http://${proxy_addr}" \
  KEYCLAW_REQUIRE_MITM_EFFECTIVE=true \
  KEYCLAW_MAX_BODY_BYTES=1048576 \
  KEYCLAW_VAULT_PATH="${home}/${tool}.vault.enc" \
  KEYCLAW_VAULT_PASSPHRASE=test-passphrase \
  KEYCLAW_CODEX_HOSTS=127.0.0.1 \
  KEYCLAW_CLAUDE_HOSTS=127.0.0.1 \
  UPSTREAM_URL="$upstream_url" \
  PAYLOAD="$payload" \
  "$bin" "$tool" exec --model smoke \
    >"${work}/${tool}.out" 2>"${work}/${tool}.err"

  wait "$upstream_pid"
  if ! grep -Fq "KEYCLAW_SECRET_" "$body_file"; then
    echo "expected ${tool} upstream body to contain a placeholder" >&2
    cat "${work}/${tool}.err" >&2
    cat "$body_file" >&2
    exit 1
  fi
}

run_doctor_smoke
run_proxy_smoke
run_mitm_smoke codex "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"
run_mitm_smoke claude "xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f"

echo "smoke ok: doctor, proxy, codex, claude"
