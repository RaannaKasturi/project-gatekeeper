import requests
import os
from dotenv import load_dotenv

load_dotenv()
cf_token = os.environ.get("CF_TOKEN")
cf_zone_id = os.environ.get("CF_ZONE_ID")
cf_email = os.environ.get("CF_EMAIL_ID")
cf_api = "https://api.cloudflare.com/client/v4/"

headers = {
    "Content-Type": "application/json",
    "X-Auth-Email": cf_email,
    "X-Auth-Key": cf_token
}

def check_txt():
    cf_endpoint = f"zones/{cf_zone_id}/dns_records"
    url = f"{cf_api}{cf_endpoint}"
    response = requests.request("GET", url, headers=headers)
    data = response.json()
    record_ids = []
    record_names = []
    for record in data['result']:
        if record['type'] == "TXT":
            record_id = record['id']
            record_name = record['name']
            record_ids.append(record_id)
            record_names.append(record_name)
        else:
            continue
    return record_ids, record_names
        
def add_txt(txt_rec, txt_value, ssl_email):
    cf_endpoint = f"zones/{cf_zone_id}/dns_records"
    url = f"{cf_api}{cf_endpoint}"
    name = txt_rec
    data = {
        "type": "TXT",
        "name": name,
        "content": txt_value,
        "proxied": False,
        "comment": f"SSL Verification for {ssl_email}"
    }
    response = requests.request("POST", url, headers=headers, json=data)
    return response.json()

def del_txt(txt_name):
    res = None
    record_ids, record_names = check_txt()
    for record_id, record_name in zip(record_ids, record_names):
        if record_name.startswith(txt_name):
            try:
                cf_endpoint = f"zones/{cf_zone_id}/dns_records/{record_id}"
                url = f"{cf_api}{cf_endpoint}"
                requests.request("DELETE", url, headers=headers)
                res = "records deleted"
            except Exception as e:
                res = f"Error deleting records: {e}"
        else:
            res = "records not found"
    return res