#!/usr/bin/python3
#   Filename: censys.py
#   Module: Censys


# Standard Libraries
import time

# External Libraries
from censys.search import CensysHosts

__version__ = "v2.0"

def port_scan(hostx, censys_id, censys_secret, counter):
    if not censys_id or not censys_secret:
        return
    try:
        c = CensysHosts(censys_id, censys_secret)
    except Exception:
        return

    for ip in hostx.resolved_ips:
        try:
            response = c.view(ip.address)
            ports = response.get("ports", [])
            if ip.ports:
                for p in ports:
                    if p not in ip.ports:
                        ip.ports.append(p)
            else:
                ip.ports = list(ports)
            counter.ports += len(ports)
        except Exception:
            # If Censys API key is invalid/decommissioned, break out immediately
            break

