#!/usr/bin/env python3
"""
LSM Agent Guard Loader — sandboxes a systemd service at the kernel level.

Reads the PID of casper-agent from systemd, writes it into the BPF map
`agent_policy`, and pre-populates `allowed_ports` with whitelisted
destination ports (443, 8545). Monitors the service for PID changes
(restarts) and updates the map automatically.

Prerequisites:
  - lsm_agent_guard.o compiled
  - BPF LSM enabled: "lsm=lockdown,yama,bpf" in kernel cmdline
  - bpftool installed
  - Root privileges

Usage:
  python3 lsm_loader.py [--service casper-agent] [--interval 10]
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

SERVICE_NAME = os.environ.get('LSM_SERVICE', 'casper-agent')
CHECK_INTERVAL = int(os.environ.get('LSM_CHECK_INTERVAL', '10'))
BPF_OBJ = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lsm_agent_guard.o')
BPF_PIN_PATH = '/sys/fs/bpf/lsm_agent_guard'

ALLOWED_PORTS = [443, 8545, 7777]

running = True


def handle_signal(signum, frame):
    global running
    running = False
    print(f'[lsm-loader] Signal {signum}, shutting down...')


def get_service_pid(service):
    """Get MainPID of a systemd service."""
    try:
        out = subprocess.check_output(
            ['systemctl', 'show', service, '-p', 'MainPID', '--value'],
            text=True, timeout=5
        ).strip()
        pid = int(out)
        return pid if pid > 0 else None
    except (subprocess.SubprocessError, ValueError):
        return None


def get_map_id(map_name):
    """Find BPF map ID by name."""
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
    subprocess.run(
        ['bpftool', 'map', 'update', 'id', str(map_id),
         'key', 'hex'] + key_hex.split() +
        ['value', 'hex'] + value_hex.split(),
        check=True, timeout=5, capture_output=True
    )


def bpf_map_delete(map_id, key_hex):
    subprocess.run(
        ['bpftool', 'map', 'delete', 'id', str(map_id),
         'key', 'hex'] + key_hex.split(),
        check=False, timeout=5, capture_output=True
    )


def pid_to_hex(pid):
    """Convert PID to 4-byte little-endian hex."""
    b = pid.to_bytes(4, byteorder='little')
    return ' '.join(f'{x:02x}' for x in b)


def port_to_hex(port):
    """Convert port number to 4-byte little-endian hex (__u32)."""
    b = port.to_bytes(4, byteorder='little')
    return ' '.join(f'{x:02x}' for x in b)


def load_lsm_prog(obj_path):
    """Load BPF LSM program via bpftool."""
    if os.path.exists(BPF_PIN_PATH):
        print(f'[lsm-loader] LSM program already pinned at {BPF_PIN_PATH}')
        return True
    try:
        subprocess.run(
            ['bpftool', 'prog', 'load', obj_path, BPF_PIN_PATH,
             'type', 'lsm'],
            check=True, timeout=10, capture_output=True
        )
        print(f'[lsm-loader] LSM program loaded and pinned at {BPF_PIN_PATH}')
        return True
    except subprocess.SubprocessError as e:
        print(f'[lsm-loader] Failed to load LSM program: {e}')
        return False


def unpin_lsm_prog():
    """Remove pinned BPF program."""
    if os.path.exists(BPF_PIN_PATH):
        os.remove(BPF_PIN_PATH)
        print(f'[lsm-loader] Unpinned LSM program from {BPF_PIN_PATH}')


def setup_allowed_ports(map_id):
    """Pre-populate allowed_ports map."""
    for port in ALLOWED_PORTS:
        key = port_to_hex(port)
        bpf_map_update(map_id, key, '01 00 00 00')
        print(f'[lsm-loader] Allowed port {port}')


def main():
    parser = argparse.ArgumentParser(description='LSM Agent Guard Loader')
    parser.add_argument('--service', default=SERVICE_NAME,
                        help='systemd service to guard')
    parser.add_argument('--interval', type=int, default=CHECK_INTERVAL,
                        help='PID check interval in seconds')
    parser.add_argument('--load', action='store_true',
                        help='Load BPF LSM program on startup')
    parser.add_argument('--unpin-on-exit', action='store_true',
                        help='Unpin BPF program on shutdown')
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if args.load:
        if not os.path.exists(BPF_OBJ):
            print(f'[lsm-loader] ERROR: {BPF_OBJ} not found. Compile first.')
            sys.exit(1)
        if not load_lsm_prog(BPF_OBJ):
            sys.exit(1)

    ports_map_id = get_map_id('allowed_ports')
    if ports_map_id is not None:
        setup_allowed_ports(ports_map_id)
    else:
        print('[lsm-loader] WARNING: allowed_ports map not found')

    print(f'[lsm-loader] Guarding service "{args.service}", '
          f'checking PID every {args.interval}s')

    current_pid = None

    while running:
        policy_map_id = get_map_id('agent_policy')
        if policy_map_id is None:
            print('[lsm-loader] agent_policy map not found. Is LSM loaded?')
            time.sleep(args.interval)
            continue

        new_pid = get_service_pid(args.service)

        if new_pid != current_pid:
            if current_pid is not None:
                key = pid_to_hex(current_pid)
                bpf_map_delete(policy_map_id, key)
                print(f'[lsm-loader] Removed old PID {current_pid}')

            if new_pid is not None:
                key = pid_to_hex(new_pid)
                bpf_map_update(policy_map_id, key, '01 00 00 00')
                print(f'[lsm-loader] Guarding PID {new_pid} ({args.service})')
            else:
                print(f'[lsm-loader] Service {args.service} not running')

            current_pid = new_pid

        time.sleep(args.interval)

    if current_pid is not None:
        policy_map_id = get_map_id('agent_policy')
        if policy_map_id:
            bpf_map_delete(policy_map_id, pid_to_hex(current_pid))
            print(f'[lsm-loader] Removed PID {current_pid} on shutdown')

    if args.unpin_on_exit:
        unpin_lsm_prog()

    print('[lsm-loader] Stopped.')


if __name__ == '__main__':
    main()
