import json
import hashlib
from urllib.request import urlopen
from tools import b64, send_signed_request, poll_until_not, check_txt_records, getDirectory, writeFile
from cryptoTools import genJWK, parse_csr, csr2Der

def get_public_key(account_key):
    jwk = genJWK(account_key)
    return json.loads(jwk)

def register_account(ca_url, account_key, email):
    print("Registering {0}...".format(email))
    directory = getDirectory(ca_url)
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
    order, order_code, order_headers = send_signed_request(getDirectory(ca_url)["newOrder"], id, getDirectory(ca_url)["newNonce"], auth, account_key, "Error creating new order")
    return order, order_headers

def dns_challenges(ca_url, auth, order, domain, thumbprint, account_key):
    challenges_info = []
    for auth_url in order["authorizations"]:
        authz_result, authz_code, authz_headers = send_signed_request(
            auth_url, None, getDirectory(ca_url)["newNonce"], auth, account_key, "Error getting authorization")
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
        challenge_url, {}, getDirectory(ca_url)["newNonce"], auth, account_key, "Error submitting challenge")
    if verification_code != 200:
        print(f"Error submitting challenge:\nUrl: {challenge_url}\nData: {json.dumps(verification_result)}\nResponse Code: {verification_code}\nResponse: {verification_result}")
        return False
    print("Challenge verified for {}!".format(challenge_url))
    return True

def finalize_order(ca_url, auth, order, order_headers, csr, account_key):
    print("Waiting for challenges to pass...")
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], getDirectory(ca_url)["newNonce"], auth, account_key, "Error checking order status")
    print(f"Order status: {order['status']}")
    if order["status"] == "valid":
        print("Order is already valid. No need to finalize again.")
        return None
    if order["status"] != "ready":
        raise ValueError("Order status is not ready for finalization")
    print("Passed challenges!")
    print("Getting certificate...")
    csr_der = csr2Der(csr)
    fnlz_resp, fnlz_code, fnlz_headers = send_signed_request(order["finalize"], {"csr": b64(csr_der)}, getDirectory(ca_url)["newNonce"], auth, account_key, "Error finalizing order")
    if fnlz_code != 200:
        raise ValueError("Failed to finalize the order")
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], getDirectory(ca_url)["newNonce"], auth, account_key, "Error checking order status after finalization")
    if order["status"] == "valid":
        print("Order finalized successfully!")
    else:
        raise ValueError("Order finalization failed")
    cert_resp, cert_code, cert_headers = send_signed_request(order["certificate"], None, getDirectory(ca_url)["newNonce"], auth, account_key, "Error getting certificate")
    if cert_code != 200:
        raise ValueError("Failed to get the certificate")
    print("Received certificate!")
    return cert_resp

def getTXT(tempPrivateFile, CSRFile, server, email):
    commonName, organization, organizationalUnit, cityLocality, stateProvince, country, domainNames, signatureAlgorithm, keyAlgorithm, keySize = parse_csr(CSRFile)
    auth = register_account(server, tempPrivateFile, email)
    order, order_headers = request_challenges(server, auth, domainNames, tempPrivateFile)
    TXTRecs = []
    TXTValues = []
    thumbprint = b64(hashlib.sha256(json.dumps(get_public_key(tempPrivateFile), sort_keys=True, separators=(',', ':')).encode()).digest())
    challenges_info = []
    for domain in domainNames:
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
        certFile = writeFile(cert, email)
    return certFile
