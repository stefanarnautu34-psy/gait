#!/usr/bin/env python3
"""
fake_implant.py - simulate the beacon behaviour of ENDLESSDOORS.
FOR TESTING ONLY, on your own network, against your own fake server.

It opens a TCP connection to a chosen host, sends a short registration
message (imitating a device id plus a MAC address), waits briefly, closes,
and repeats every ~35 seconds. No TLS, no DNS (it connects straight to an IP),
no authentication. This is exactly the shape GAIT is meant to catch.

Pair it with a listener on the other machine, for example:
    ncat -lk -p 7000

Usage:
    python3 fake_implant.py 192.168.88.91 7000
    python3 fake_implant.py 192.168.88.91 7000 --count 6 --interval 35
"""

import argparse
import random
import socket
import sys
import time
from datetime import datetime


def beacon(host, port, timeout):
    """A single phone-home. Returns True on success."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        print(f"  connection failed: {exc}")
        return False
    try:
        fake_mac = "aa:bb:cc:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        payload = f"ROUTER_AX3000;{fake_mac};online".encode()
        s.sendall(payload)
        s.settimeout(1.0)
        try:
            s.recv(256)
        except socket.timeout:
            pass
        return True
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(
        description="ENDLESSDOORS beacon simulator (testing only).")
    ap.add_argument("host", help="IP of the fake server")
    ap.add_argument("port", type=int, help="C2 port, e.g. 7000")
    ap.add_argument("--count", type=int, default=8,
                    help="how many beacons to send (default 8)")
    ap.add_argument("--interval", type=float, default=35,
                    help="seconds between beacons (default 35)")
    ap.add_argument("--jitter", type=float, default=1.5,
                    help="random variation +/- seconds (default 1.5)")
    ap.add_argument("--timeout", type=float, default=5,
                    help="connection timeout in seconds")
    args = ap.parse_args()

    print(f"Simulating beacon to {args.host}:{args.port}")
    print(f"{args.count} connections at ~{args.interval}s intervals. "
          f"Ctrl+C to stop.\n")

    ok = 0
    for i in range(1, args.count + 1):
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{stamp}] beacon {i}/{args.count} -> {args.host}:{args.port}", end="  ")
        if beacon(args.host, args.port, args.timeout):
            ok += 1
            print("ok")
        if i < args.count:
            wait = args.interval + random.uniform(-args.jitter, args.jitter)
            time.sleep(max(0.5, wait))

    print(f"\nDone. {ok}/{args.count} connections succeeded.")
    print("Now run engine.py on eve.json to see whether it was detected.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
