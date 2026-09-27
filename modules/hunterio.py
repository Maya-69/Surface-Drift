#!/usr/bin/python3
#   Filename: hunterio.py
#   Module: HunterIO
#   Attack Surface Mapper (ASM)

# https://api.hunter.io/v2/domain-search?domain=

# Standard Libraries
import json

# External Libraries
import requests


def _guess_email(pattern, first, last, domain):
    if not pattern or not domain or not (first or last):
        return ""
    f = first[0].lower() if first else ""
    l = last[0].lower() if last else ""
    first_clean = first.lower() if first else ""
    last_clean = last.lower() if last else ""
    try:
        local = pattern.replace("{f}", f).replace("{l}", l).replace("{first}", first_clean).replace("{last}", last_clean)
        return f"{local}@{domain}"
    except Exception:
        return ""


def query(hostx, key):
    try:
        domain = hostx.primary_domain
        par = {'domain': domain, 'api_key': key}
        user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
        req = requests.get("https://api.hunter.io/v2/domain-search", params=par, headers=user_agent, timeout=10)
        hunterio_api = json.loads(req.text)

        pattern = hunterio_api.get("data", {}).get("pattern", "")
        if pattern:
            hostx.pattern = pattern

        emails_data = hunterio_api.get("data", {}).get("emails", [])
        for item in emails_data:
            email = item.get("value", "")
            if email and email not in hostx.emails:
                hostx.emails.append(email)

            first_name = (item.get("first_name") or "").strip()
            last_name = (item.get("last_name") or "").strip()
            full_name = f"{first_name} {last_name}".strip()
            linkedin = item.get("linkedin") or ""
            
            if full_name or email:
                employee_record = [email, full_name, first_name, last_name, linkedin]
                if employee_record not in hostx.employees:
                    hostx.employees.append(employee_record)

            if pattern and first_name and last_name:
                guessed = _guess_email(pattern, first_name, last_name, domain)
                if guessed and guessed not in hostx.guessed_emails and guessed != email:
                    hostx.guessed_emails.append(guessed)

    except Exception:
        pass

