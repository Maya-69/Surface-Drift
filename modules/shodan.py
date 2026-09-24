#!/usr/bin/python3
#   Filename: shodan.py
#   Module: Shodan


# Standard Libraries
import time

# External Libraries
import shodan


def port_scan(hostx, key, counter):
    if not key or len(key) != 32:
        return
    try:
        api = shodan.Shodan(key)
    except Exception:
        return

    # Check up to 15 unique IPs to avoid hitting API limits
    scanned_ips = set()
    for IP in hostx.resolved_ips:
        if IP.address in scanned_ips or len(scanned_ips) >= 15:
            continue
        scanned_ips.add(IP.address)

        try:
            query = api.host(IP.address)
            IP.ports = query.get('ports', [])
            IP.vulns = query.get('vulns', [])
            IP.server = query.get('server', '')
            counter.ports += len(IP.ports)
            counter.vulns += len(IP.vulns)
        except Exception:
            continue

