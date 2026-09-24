#!/usr/bin/python3
#   Filename: dnsdumpster.py
#   Module: DNSdumpster


# Standard Libraries
import os

# External Libraries
import requests

DNS_DUMPSTER = 'https://dnsdumpster.com/'


# get_map Function - Downloads DNS Map from dnsdumpster.com
def get_map(hostx, out_path):
    headers = {'user-agent': "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
               'Referer': DNS_DUMPSTER}
    map_url = "{0}static/map/{1}.png".format(DNS_DUMPSTER, str(hostx.primary_domain))
    map_path = os.path.join(out_path, str(hostx.primary_domain) + "_map.png")

    if hostx.primary_domain == "":
        return None
    try:

        res1 = requests.get(DNS_DUMPSTER, headers=headers, timeout=10)
        csrftoken = res1.cookies.get('csrftoken')
        if not csrftoken:
            return ""
        data = {
            'csrfmiddlewaretoken': csrftoken,
            'targetip': hostx.primary_domain
        }

        headers = {'user-agent': "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
                   'Referer': DNS_DUMPSTER, 'Cookie': 'csrftoken=' + csrftoken}
        requests.post(DNS_DUMPSTER, data=data, headers=headers, timeout=10)

        response = requests.get(map_url, headers=headers, timeout=10)
        # print("Response Status: " + response.status_code) # Debug Statement
        if response.status_code == 200:

            try:
                os.makedirs(out_path, exist_ok=True)
            except Exception:
                pass
            with open(map_path, 'wb') as new_file:
                new_file.write(response.content)
        return map_path
    except:
        return ""
