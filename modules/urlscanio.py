#!/usr/bin/python3
#   Filename: urlscanio.py
#   Module: URLScanIO Module


# Standard Libraries
import json

# External Libraries
import requests

import asm


def get_domain(IP):
    # print (ip.address)
    # $ curl -v --url "https://urlscan.io/api/v1/search?ip=<IP>"
    user_agent = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
    try:
        response = requests.get('https://urlscan.io/api/v1/search?q=ip:' + IP, headers=user_agent, timeout=10)
        api = json.loads(response.text)
        if api['total'] == 0:
            return
        try:
            return api['results'][0]['page']['domain']
        except:
            pass
    except:
        pass


def query(hostx):
    scanned_ips = set()
    for ip in hostx.resolved_ips:
        if ip.address in scanned_ips or len(scanned_ips) >= 10:
            continue
        scanned_ips.add(ip.address)

        par = {'q': ip.address}
        user_agent = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
        try:
            response = requests.get("https://urlscan.io/api/v1/search", params=par, headers=user_agent, timeout=5)
            api = json.loads(response.text)
            if api.get('total', 0) == 0:
                continue

            results = api.get('results', [])
            if results:
                page = results[0].get('page', {})
                city = page.get('city', '')
                country = page.get('country', '')
                if city or country:
                    ip.location = f"{city}, {country}".strip(", ")
                if page.get('asn'):
                    ip.asn = str(page.get('asn'))
                if page.get('asnname'):
                    ip.asn_name = str(page.get('asnname'))
                if not ip.server and page.get('server'):
                    ip.server = str(page.get('server'))

                for item in results:
                    domain = item.get('page', {}).get('domain', '')
                    if domain and domain not in hostx.hname:
                        hostx.hname.append(domain)
        except Exception:
            continue

    return
