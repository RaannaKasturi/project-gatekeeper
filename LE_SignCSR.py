import json
import binascii
import hashlib
import re
from urllib.request import urlopen
from tools import cmd, b64, send_signed_request, poll_until_not, check_txt_records

__version__ = "0.3.0"

def get_directory(ca_url):
    global CA_DIR
    CA_DIR = json.loads(urlopen(ca_url).read().decode("utf8"))
    return CA_DIR

def get_public_key(account_key):
    print("Decoding private key...")
    out = cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="Error reading account public key")
    pub_hex, pub_exp = re.search(r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)", out.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex))
    pub_mod64 = b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = b64(pub_exp)
    jwk = {"e": pub_exp64, "kty": "RSA", "n": pub_mod64}
    print("Found public key!")
    return jwk

def get_csr_domains(csr):
    print("Reading csr file...")
    out = cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error reading CSR")
    domains = set()
    cn = None
    common_name = re.search(r"Subject:.*? CN *= *([^\s,;/]+)", out.decode("utf8"))
    if common_name is not None:
        domains.add(common_name.group(1))
        cn = common_name.group(1).split(".")[0]
    subj_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode("utf8"), re.MULTILINE | re.DOTALL)
    if subj_alt_names is not None:
        for san in subj_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                dm = san[4:]
                if cn is None and dm.find("*") == -1:
                    cn = dm
                domains.add(dm)
    print("Found domains {}".format(", ".join(domains)))
    return domains, cn

def register_account(ca_url, account_key, email):
    print("Registering {0}...".format(email))

    # Debugging: Print the directory content and type
    directory = get_directory(ca_url)
    try:
        tos = directory["meta"]["termsOfService"]
    except KeyError:
        raise KeyError("The 'meta' or 'termsOfService' key is missing in the directory response.")

    print(f"By continuing you are agreeing to Issuer's Subscriber Agreement\n{tos}")
    reg = {"termsOfServiceAgreed": True}
    nonce_url = directory["newNonce"]
    auth = {"jwk": get_public_key(account_key)}
    acct_headers = None

    result, code, acct_headers = send_signed_request(directory["newAccount"], reg, nonce_url, auth, account_key, "Error registering")
    if code == 201:
        print("Registered!")
    else:
        print("Already registered!")
    auth = {"kid": acct_headers["Location"]}
    print("Updating account...")
    ua_result, ua_code, ua_headers = send_signed_request(acct_headers["Location"], {"contact": ["mailto:{}".format(email)]}, nonce_url, auth, account_key, "Error updating account")
    print("Done")
    return auth


def request_challenges(ca_url, auth, domains, account_key):
    print("Making new order for {0}...".format(", ".join(list(domains))))
    id = {"identifiers": []}
    for domain in domains:
        id["identifiers"].append({"type": "dns", "value": domain})
    order, order_code, order_headers = send_signed_request(get_directory(ca_url)["newOrder"], id, get_directory(ca_url)["newNonce"], auth, account_key, "Error creating new order")
    return order, order_headers

def dns_challenges(ca_url, auth, order, domain, thumbprint, account_key):
    challenges_info = []
    for auth_url in order["authorizations"]:
        authz_result, authz_code, authz_headers = send_signed_request(
            auth_url, None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting authorization")
        challenge = next((c for c in authz_result["challenges"] if c["type"] == "dns-01" and authz_result["identifier"]["value"] == domain), None)
        if challenge:
            token = challenge["token"]
            key_authorization = "{}.{}".format(token, thumbprint)
            chl_verification = b64(hashlib.sha256(key_authorization.encode()).digest())
            TXTRec = "_acme-challenge.{}".format(domain)
            TXTValue = chl_verification
            challenges_info.append((TXTRec, TXTValue, challenge["url"]))
    return challenges_info


def dns_verification(ca_url, auth, challenge_url, account_key):
    print("Requesting verification for {}...".format(challenge_url))
    verification_result, verification_code, verification_headers = send_signed_request(
        challenge_url, {}, get_directory(ca_url)["newNonce"], auth, account_key, "Error submitting challenge")
    if verification_code != 200:
        print(f"Error submitting challenge:\nUrl: {challenge_url}\nData: {json.dumps(verification_result)}\nResponse Code: {verification_code}\nResponse: {verification_result}")
        return False
    print("Challenge verified for {}!".format(challenge_url))
    return True

def finalize_order(ca_url, auth, order, order_headers, csr, account_key):
    print("Waiting for challenges to pass...")
    # Polling until the order status is not pending or processing
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status")
    # Check if the order status is already valid
    print(f"Order status: {order['status']}")
    if order["status"] == "valid":
        print("Order is already valid. No need to finalize again.")
        return None
    if order["status"] != "ready":
        raise ValueError("Order status is not ready for finalization")
    print("Passed challenges!")
    print("Getting certificate...")
    # Converting CSR to DER format
    csr_der = cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    # Finalizing the order
    fnlz_resp, fnlz_code, fnlz_headers = send_signed_request(order["finalize"], {"csr": b64(csr_der)}, get_directory(ca_url)["newNonce"], auth, account_key, "Error finalizing order")
    if fnlz_code != 200:
        raise ValueError("Failed to finalize the order")
    # Polling until the order status is not pending or processing
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status after finalization")
    if order["status"] == "valid":
        print("Order finalized successfully!")
    else:
        raise ValueError("Order finalization failed")
    # Getting the certificate
    cert_resp, cert_code, cert_headers = send_signed_request(order["certificate"], None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting certificate")
    if cert_code != 200:
        raise ValueError("Failed to get the certificate")
    print("Received certificate!")
    return cert_resp

def save_cert(data, email):
    certs = data.split('-----BEGIN CERTIFICATE-----\n')[1:]
    caFile = f"{email.split('@')[0]}/CACertificate.pem"
    certFile  = f"{email.split('@')[0]}/Certificate.pem"
    for i, cert in enumerate(certs, 1):
        # Preparing certificate content with BEGIN/END headers
        if i == 1:
            file_name = certFile
        elif i == 2:
            file_name = caFile
        cert_content = f"-----BEGIN CERTIFICATE-----\n{cert.strip()}"
        with open(file_name, 'w') as f:
            f.write(cert_content)
            f.write('\n')
    return certFile, caFile

def getTXT(tempPrivateFile, CSRFile, server, email):
    domains, common_name = get_csr_domains(CSRFile)
    auth = register_account(server, tempPrivateFile, email)
    order, order_headers = request_challenges(server, auth, domains, tempPrivateFile)
    TXTRecs = []
    TXTValues = []
    thumbprint = b64(hashlib.sha256(json.dumps(get_public_key(tempPrivateFile), sort_keys=True, separators=(',', ':')).encode()).digest())
    challenges_info = []
    for domain in domains:
        challenges = dns_challenges(server, auth, order, domain, thumbprint, tempPrivateFile)
        challenges_info.extend(challenges)
    for TXTRec, TXTValue, challenge_url in challenges_info:
        TXTRecs.append(TXTRec)
        TXTValues.append(TXTValue)
    return challenges_info, auth, order, order_headers, TXTRecs, TXTValues

def getCert(tempPrivateFile, CSRFile, challenges_info, auth, order, order_headers, server, email):
    for TXTRec, TXTValue, challenge_url in challenges_info:
        success = check_txt_records(TXTRec, TXTValue)
        if not success:
            print("DNS verification failed for {}. Exiting.".format(TXTRec))
            return None, None
        dns_success = dns_verification(server, auth, challenge_url, tempPrivateFile)
        if not dns_success:
            print("DNS verification failed for {}. Exiting.".format(challenge_url))
            return None, None
        else:
            print(f"DNS verification successful for {challenge_url}")
            continue
    cert = finalize_order(server, auth, order, order_headers, CSRFile, tempPrivateFile)
    if cert:
        certFile, caFile = save_cert(cert, email)
    return certFile, caFile

#python3 test.py --account-key raannakasturi/tempPrivate.pem --csr raannakasturi/domain.csr --email raannakasturi@gmail.com --dns
