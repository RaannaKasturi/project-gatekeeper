import requests
import os
from dotenv import load_dotenv

load_dotenv()
cftoken = os.environ.get("CF_TOKEN")
cfzoneid = os.environ.get("CF_ZONE_ID")
cfemail = os.environ.get("CF_EMAIL_ID")
CF_API = "https://api.cloudflare.com/client/v4/"

headers = {
    "Content-Type": "application/json",
    "X-Auth-Email": cfemail,
    "X-Auth-Key": cftoken
}

def checkTXT(TXTRecs):
    cf_endpoint = f"zones/{cfzoneid}/dns_records"
    url = f"{CF_API}{cf_endpoint}"
    response = requests.request("GET", url, headers=headers)
    data = response.json()
    recordIDs = []
    recordNames = []
    for record in data['result']:
        if record['type'] == "TXT":
            recordID = record['id']
            recordName = record['name']
            recordIDs.append(recordID)
            recordNames.append(recordName)
        else:
            continue
    return recordIDs, recordNames
        
def addTXT(TXTRec, TXTValue, SSLEmail):
    cf_endpoint = f"zones/{cfzoneid}/dns_records"
    url = f"{CF_API}{cf_endpoint}"
    name = TXTRec
    data = {
        "type": "TXT",
        "name": name,
        "content": TXTValue,
        "proxied": False,
        "comment": f"SSL Verification for {SSLEmail}"
    }
    response = requests.request("POST", url, headers=headers, json=data)
    return response.json()

def delTXT(TXTName):
    res = None
    recordIDs, recordNames = checkTXT(TXTName)
    for recordID, recordName in zip(recordIDs, recordNames):
        if recordName.startswith(TXTName):
            try:
                cf_endpoint = f"zones/{cfzoneid}/dns_records/{recordID}"
                url = f"{CF_API}{cf_endpoint}"
                requests.request("DELETE", url, headers=headers)
                res = f"records deleted"
            except:
                res = f"error deleting records"
        else:
            res = f"records not found"
            continue
    return res