import base64
import json
import sys
import time
import urllib.request
import dns.resolver
from urllib.error import URLError
from urllib.request import urlopen
from cryptoTools import sign

def getDirectory(ca_url):
    global CA_DIR
    CA_DIR = json.loads(urlopen(ca_url).read().decode("utf8"))
    return CA_DIR

def writeFile(data, email):
    certFile  = f"{email.split('@')[0]}/Certificate.pem"
    file_name = certFile
    with open(file_name, 'w') as f:
        f.write(data)
        f.write('\n')
    return certFile

def b64(b):
    "Convert bytes to JWT base64 string"
    if type(b) is str:
        b = b.encode()
    return base64.urlsafe_b64encode(b).decode().replace("=", "")

def do_request(url, data=None, err_msg="Error"):
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/jose+json",
                    "User-Agent": "project-gatekeeper",
                },
            )
        )
        resp_data, code, headers = (
            resp.read().decode("utf8"),
            resp.getcode(),
            resp.headers,
        )
    except URLError as e:
        resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # resp_data is not a JSON string; that's fine
    return resp_data, code, headers

def mk_signed_req_body(url, payload, nonce, auth, account_key):
    if len(nonce) < 1:
        sys.stderr.write("_mk_signed_req_body: nonce invalid: {}".format(nonce))
        sys.exit(1)
    payload64 = "" if payload is None else b64(json.dumps(payload).encode("utf8"))
    protected = {"url": url, "alg": "RS256", "nonce": nonce}
    protected.update(auth)
    protected64 = b64(json.dumps(protected).encode("utf8"))
    protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
    signature = sign(account_key, protected_input)
    return json.dumps(
        {"protected": protected64, "payload": payload64, "signature": b64(signature)}
    )

def send_signed_request(url, payload, nonce_url, auth, account_key, err_msg):
    """Make signed request to ACME endpoint"""
    tried = 0
    nonce = do_request(nonce_url)[2]["Replay-Nonce"]
    while True:
        data = mk_signed_req_body(url, payload, nonce, auth, account_key)
        resp_data, resp_code, headers = do_request(
            url, data=data.encode("utf8"), err_msg=err_msg
        )
        if resp_code in [200, 201, 204]:
            return resp_data, resp_code, headers
        elif (
            resp_code == 400
            and resp_data.get("type", "") == "urn:ietf:params:acme:error:badNonce"
            and tried < 100
        ):
            nonce = headers.get("Replay-Nonce", "")
            tried += 1
            continue
        else:
            sys.stderr.write(
                "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
                    err_msg, url, data, resp_code, resp_data
                )
            )
            sys.exit(1)

def poll_until_not(url, pending_statuses, nonce_url, auth, account_key, err_msg):
    result, t0, delay = None, time.time(), 5  # Increase initial delay to 5 seconds
    while result is None or result["status"] in pending_statuses:
        assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
        print(f"Checking order status: {result['status'] if result else 'None'}")
        time.sleep(delay)
        delay = min(delay * 2, 120)  # Increase the delay, up to a maximum of 120 seconds
        result, _, _ = send_signed_request(
            url, None, nonce_url, auth, account_key, err_msg
        )
        print(f"Final order status: {result['status']}")
    return result

def get_cname_target(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None


def get_txt_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            return rdata.to_text().strip('"')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def check_txt_records(domain, expected_value):
    cname_target = get_cname_target(domain)
    if cname_target:
        txt_value = get_txt_record(cname_target)
        print(f"TXT value: {txt_value}")
        print(f"Expected value: {expected_value}")
        if txt_value == expected_value:
            return True
    else:
        txt_value = get_txt_record(domain)
        print(f"TXT value: {txt_value}")
        print(f"Expected value: {expected_value}")
        if txt_value == expected_value:
            return True
    return False
