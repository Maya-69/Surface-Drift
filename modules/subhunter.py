#!/usr/bin/python3
#   Filename: subhunter.py
#   Module: SubHunter


# Standard Libraries
import time
import colorama
import ipaddress
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
# External Libraries
import requests
from colorama import Fore, Style
from validator_collection import checkers

from modules import subbrute
from subprocess import STDOUT, check_output

class TargetIP:
    def __init__(self, addr):
        self.address = addr
        self.hostname = []
        self.ports = []
        self.asn = ""
        self.asn_name = ""
        self.server = ""
        self.vulns = []
        self.cidr = ""
        self.location = ""
        self.country = ""

def cprint(type, msg, reset):
    message = {
        "action": Fore.YELLOW,
        "positive": Fore.GREEN + Style.BRIGHT,
        "info": Fore.YELLOW,
        "reset": Style.RESET_ALL,
        "red": Fore.RED,
        "white": Fore.WHITE,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW
    }
    style = message.get(type.lower(), "")

    if type == "error":
        print("{0}\n[*] Error: {1}".format(Fore.RED + Style.BRIGHT, Style.RESET_ALL + Fore.WHITE + msg))
    else:
        print(style + msg, end="")
    if (reset == 1):
        print(Style.RESET_ALL)


def query_crtsh(domain):
    subs = set()
    try:
        cprint("info", "[-] Querying Certificate Transparency (crt.sh) . . .\n", 1)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=headers, timeout=8)
        if resp.status_code == 200:
            for item in resp.json():
                name_value = item.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if "*" in sub:
                        sub = sub.replace("*.", "")
                    if sub and sub.endswith(domain) and sub != domain:
                        subs.add(sub)
    except Exception:
        pass
    return list(subs)


def query_hackertarget(domain):
    subs = set()
    try:
        cprint("info", "[-] Querying HackerTarget DNS . . .\n", 1)
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=6)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                parts = line.split(",")
                if parts:
                    host = parts[0].strip().lower()
                    if host and host.endswith(domain) and host != domain:
                        subs.add(host)
    except Exception:
        pass
    return list(subs)


def passive_query(hostx, key):
    # Free OSINT Sources (no API key required)
    crt_subs = query_crtsh(hostx.primary_domain)
    for s in crt_subs:
        if s not in hostx.subdomains:
            hostx.subdomains.append(s)

    ht_subs = query_hackertarget(hostx.primary_domain)
    for s in ht_subs:
        if s not in hostx.subdomains:
            hostx.subdomains.append(s)

    # VirusTotal API (if key configured)
    if key and len(key) > 10:
        cprint("info", "[-] Querying VirusTotal API . . .\n", 1)
        par = {'apikey': key, 'domain': hostx.primary_domain}
        try:
            response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=par, timeout=6)
            tv_api = response.json()

            try:
                for sibling in tv_api.get("domain_siblings", []):
                    if sibling and sibling not in hostx.subdomains:
                        hostx.subdomains.append(sibling)
            except Exception:
                pass

            try:
                for subdomain in tv_api.get("subdomains", []):
                    if subdomain and subdomain not in hostx.subdomains:
                        hostx.subdomains.append(subdomain)
            except Exception:
                pass
        except Exception:
            cprint("error", "[*] Error: connecting with VirusTotal API", 1)


_PUBLIC_DNS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]


def _get_fast_resolver():
    try:
        res = dns.resolver.Resolver(configure=True)
        res.nameservers = _PUBLIC_DNS
        res.timeout = 0.8
        res.lifetime = 1.0
        return res
    except Exception:
        return dns.resolver.Resolver()


_fast_resolver = _get_fast_resolver()


def _resolve_name(name):
    try:
        answers = _fast_resolver.resolve(name, "A")
        return name, sorted({answer.address for answer in answers})
    except Exception:
        return name, []


def _process_candidate_batch(batch, hostx, existing_subs, known_ips, mswitch, max_workers=60):
    """Resolve a bounded chunk of candidates and register live findings."""
    live_found = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve_name, cand): cand for cand in batch}
        for future in as_completed(futures):
            name, addresses = future.result()
            if not addresses:
                continue

            live_found.add(name)
            if name not in existing_subs:
                existing_subs.add(name)
                hostx.subdomains.append(name)
                if mswitch.verbose:
                    cprint("positive", f"[+] Discovered Subdomain: {name}", 1)

            for address in addresses:
                try:
                    if ipaddress.ip_address(address).is_private:
                        continue
                except ValueError:
                    continue

                if address not in known_ips:
                    known_ips.add(address)
                    target_ip = TargetIP(address)
                    target_ip.hostname.append(name)
                    hostx.resolved_ips.append(target_ip)
                    cprint("white", "	|", 1)
                    cprint("white", f"  [{address}] ({name})", 1)
                    if mswitch.verbose:
                        cprint("info", f"[i] Adding target IPv4: {address}", 1)
                else:
                    for tip in hostx.resolved_ips:
                        if tip.address == address and name not in tip.hostname:
                            tip.hostname.append(name)
    return live_found


def active(mswitch, hostx, wordlist, subwordlist, recursive=False):
    """Enumerate in-scope A records using high-speed chunked batching and live parent recursion."""
    if not hostx.primary_domain:
        return False

    domain = hostx.primary_domain
    existing = set(hostx.subdomains)
    known_ips = {ip.address for ip in hostx.resolved_ips}
    discovered_live = set(existing)

    cprint("info", f"[-] Initiating high-speed active DNS brute-forcing for {domain} . . .\n", 1)

    try:
        with open(wordlist, "rt", encoding="utf-8", errors="ignore") as source:
            raw_labels = [line.strip().lower() for line in source if line.strip() and not line.startswith("#")]
    except OSError as error:
        cprint("error", f"[*] Unable to read subdomain wordlist: {error}", 1)
        return False

    seen_candidates = set()
    root_candidates = []
    for label in raw_labels:
        cand = label if label.endswith("." + domain) else f"{label}.{domain}"
        if cand != domain and cand not in seen_candidates and cand not in existing:
            seen_candidates.add(cand)
            root_candidates.append(cand)

    chunk_size = 250
    total_candidates = len(root_candidates)
    if mswitch.verbose or total_candidates > 300:
        cprint("info", f"[i] Rapid-probing {total_candidates} candidate hostnames (60 threads, RAM < 25MB)...\n", 1)

    for i in range(0, total_candidates, chunk_size):
        chunk = root_candidates[i:i + chunk_size]
        new_live = _process_candidate_batch(chunk, hostx, existing, known_ips, mswitch, max_workers=60)
        discovered_live.update(new_live)

    # Recursive Child Subdomain Brute-Forcing (ONLY on verified live parent subdomains!)
    if recursive:
        try:
            with open(subwordlist, "rt", encoding="utf-8", errors="ignore") as source:
                child_labels = [line.strip().lower() for line in source if line.strip() and not line.startswith("#")]
        except OSError as error:
            cprint("error", f"[*] Unable to read child subdomain wordlist: {error}", 1)
            child_labels = []

        if child_labels and discovered_live:
            valid_parents = [p for p in discovered_live if p.endswith(domain) and p != domain]
            # Prioritize top 20 active parents and top 50 child prefixes for high-impact discovery in ~15-20s
            valid_parents = valid_parents[:20]
            child_labels = child_labels[:50]

            cprint("info", f"[-] Expanding recursively across {len(valid_parents)} live parent subdomains ({len(child_labels)} prefixes each)...\n", 1)

            rec_candidates = []
            for parent in valid_parents:
                for child in child_labels:
                    cand = f"{child}.{parent}"
                    if cand not in existing and cand not in seen_candidates:
                        seen_candidates.add(cand)
                        rec_candidates.append(cand)

            total_rec = len(rec_candidates)
            for i in range(0, total_rec, chunk_size):
                chunk = rec_candidates[i:i + chunk_size]
                _process_candidate_batch(chunk, hostx, existing, known_ips, mswitch, max_workers=60)

    return True
