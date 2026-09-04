#!/usr/bin/env python3
"""
XDP Threat Filter Loader — bridges Silicon DNA's ban list to the kernel XDP program.

Every SYNC_INTERVAL seconds, reads the current banned-IP set from Silicon DNA's
localhost-only /api/admin/xdp-sync endpoint, then updates the BPF hash map
`blocked_ips` so the XDP program drops matching packets at the NIC driver level.

Prerequisites:
  - xdp_threat_filter.o compiled (see xdp_threat_filter.c header)
  - XDP program attached: ip link set dev eth0 xdpgeneric obj xdp_threat_filter.o sec xdp
  - bpftool installed (for map manipulation)
  - Root privileges

Usage:
  python3 xdp_loader.py [--interface eth0] [--interval 5] [--silicon-url http://127.0.0.1:3001]
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.request

SYNC_INTERVAL = int(os.environ.get('XDP_SYNC_INTERVAL', '5'))
SILICON_URL = os.environ.get('SILICON_URL', 'http://127.0.0.1:3001')
INTERFACE = os.environ.get('XDP_INTERFACE', 'eth0')
BPF_OBJ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xdp_threat_filter.o')

running = True

def handle_signal(signum, frame):
    global running
    running = False
    print(f'[xdp-loader] Signal {signum}, shutting down...')


def ip_to_u32_le(ip_str):
    """Convert dotted IPv4 to little-endian __be32 (network byte order as stored by kernel)."""
    return struct.unpack('<I', socket.inet_aton(ip_str))[0]


def get_map_id(map_name='blocked_ips'):
    """Find the BPF map ID by name using bpftool."""
    try:
        out = subprocess.check_output(
            ['bpftool', 'map', 'list', '-j'], text=True, timeout=5
        )
        maps = json.loads(out)
        for m in maps:
            if m.get('name') == map_name:
                return m['id']
    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError):
        pass
    return None


def bpf_map_update(map_id, key_hex, value_hex):
    """Update a single key in a BPF map via bpftool."""
    subprocess.run(
        ['bpftool', 'map', 'update', 'id', str(map_id),
         'key', 'hex'] + key_hex.split() +
        ['value', 'hex'] + value_hex.split(),
        check=True, timeout=5, capture_output=True
    )


def bpf_map_delete(map_id, key_hex):
    """Delete a single key from a BPF map via bpftool."""
    subprocess.run(
        ['bpftool', 'map', 'delete', 'id', str(map_id),
         'key', 'hex'] + key_hex.split(),
        check=False, timeout=5, capture_output=True
    )


def ip_to_hex(ip_str):
    """Convert dotted IPv4 to space-separated hex bytes (network byte order)."""
    octets = socket.inet_aton(ip_str)
    return ' '.join(f'{b:02x}' for b in octets)


def fetch_banned_ips(base_url):
    """Fetch the current banned IP set from Silicon DNA."""
    url = f'{base_url}/api/admin/xdp-sync'
    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return set(data.get('ips', []))
    except Exception as e:
        print(f'[xdp-loader] fetch error: {e}')
        return None


def attach_xdp(interface, obj_path):
    """Attach XDP program in generic mode."""
    subprocess.run(
        ['ip', 'link', 'set', 'dev', interface, 'xdpgeneric', 'obj', obj_path, 'sec', 'xdp'],
        check=True, timeout=10
    )
    print(f'[xdp-loader] XDP attached to {interface} (generic mode)')


def detach_xdp(interface):
    """Detach XDP program."""
    subprocess.run(
        ['ip', 'link', 'set', 'dev', interface, 'xdpgeneric', 'off'],
        check=False, timeout=10
    )
    print(f'[xdp-loader] XDP detached from {interface}')


def main():
    parser = argparse.ArgumentParser(description='XDP Threat Filter Loader')
    parser.add_argument('--interface', default=INTERFACE)
    parser.add_argument('--interval', type=int, default=SYNC_INTERVAL)
    parser.add_argument('--silicon-url', default=SILICON_URL)
    parser.add_argument('--attach', action='store_true', help='Attach XDP on startup')
    parser.add_argument('--detach-on-exit', action='store_true', help='Detach XDP on shutdown')
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if args.attach:
        if not os.path.exists(BPF_OBJ):
            print(f'[xdp-loader] ERROR: {BPF_OBJ} not found. Compile first.')
            sys.exit(1)
        attach_xdp(args.interface, BPF_OBJ)

    print(f'[xdp-loader] Syncing banned IPs every {args.interval}s from {args.silicon_url}')

    prev_ips = set()

    while running:
        map_id = get_map_id()
        if map_id is None:
            print('[xdp-loader] BPF map "blocked_ips" not found. Is XDP attached?')
            time.sleep(args.interval)
            continue

        current_ips = fetch_banned_ips(args.silicon_url)
        if current_ips is None:
            time.sleep(args.interval)
            continue

        to_add = current_ips - prev_ips
        to_remove = prev_ips - current_ips

        for ip in to_add:
            try:
                key_hex = ip_to_hex(ip)
                bpf_map_update(map_id, key_hex, '01 00 00 00')
                print(f'[xdp-loader] + blocked {ip}')
            except Exception as e:
                print(f'[xdp-loader] add error {ip}: {e}')

        for ip in to_remove:
            try:
                key_hex = ip_to_hex(ip)
                bpf_map_delete(map_id, key_hex)
                print(f'[xdp-loader] - unblocked {ip}')
            except Exception as e:
                print(f'[xdp-loader] remove error {ip}: {e}')

        if to_add or to_remove:
            print(f'[xdp-loader] Sync: {len(current_ips)} IPs blocked (+{len(to_add)}/-{len(to_remove)})')

        prev_ips = current_ips
        time.sleep(args.interval)

    if args.detach_on_exit:
        detach_xdp(args.interface)

    print('[xdp-loader] Stopped.')


if __name__ == '__main__':
    main()
