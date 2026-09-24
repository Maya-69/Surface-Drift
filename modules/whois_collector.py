#!/usr/bin/python3
#   Filename: whois_collector.py
#   Module: Whois Collector


# External Libraries
from ipwhois import IPWhois


def wlookup(hostx):
    seen_subnets = set()
    for ip in hostx.resolved_ips:
        subnet_key = ".".join(ip.address.split(".")[:3])
        if subnet_key in seen_subnets or len(seen_subnets) >= 10:
            continue
        seen_subnets.add(subnet_key)

        try:
            ip_object = IPWhois(ip.address)
            query = ip_object.lookup_rdap(depth=1)
            ip.location = query.get('asn_country_code') or ip.location
            ip.asn = query.get('asn') or ip.asn
            ip.cidr = query.get('asn_cidr') or ip.cidr
        except Exception:
            pass

