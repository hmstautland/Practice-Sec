#!/usr/bin/env python3
"""A passive network observer: forwards TCP traffic and prints what it sees.

Usage:  python3 docs/attack-scripts/01-eavesdrop.py [listen_port=5081] [target_port=5080]
Then, in another terminal, log in *through the proxy*:
  curl -s -X POST http://localhost:5081/api/auth/login -H 'Content-Type: application/json' \
       -d '{"username":"alice","password":"password123"}'
Anyone on the same Wi-Fi / router / ISP hop sees exactly this. Point it at the HTTPS port
(and use https://localhost:5081 with curl -k) to see what the observer gets once TLS is on.
"""
import socket, sys, threading

args = sys.argv[1:]
listen = int(args[0]) if len(args) > 0 else 5081
target = int(args[1]) if len(args) > 1 else 5080

def pipe(src, dst, label):
    try:
        while data := src.recv(4096):
            print(f"--- {label} ({len(data)} bytes) ---")
            print(data.decode("utf-8", errors="replace"))
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen)); srv.listen()
print(f"eavesdropping on :{listen} -> :{target}")
while True:
    client, _ = srv.accept()
    upstream = socket.create_connection(("127.0.0.1", target))
    threading.Thread(target=pipe, args=(client, upstream, "client -> server"), daemon=True).start()
    threading.Thread(target=pipe, args=(upstream, client, "server -> client"), daemon=True).start()
