import json
import hashlib
from urllib.request import urlopen
from tools import b64, send_signed_request, poll_until_not, check_txt_records, get_directory, write_file
from cryptoTools import gen_jwk, parse_csr, csr_to_der

def get_public_key(account_key):
    jwk = gen_jwk(account_key)
    return json.loads(jwk)

def register_account(ca_url, account_key, email):
    print("Registering {0}...".format(email))
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
    _result, code, acct_headers = send_signed_request(directory["newAccount"], reg, nonce_url, auth, account_key, "Error registering")
    if code == 201:
        print("Registered!")
    else:
        print("Already registered!")
    auth = {"kid": acct_headers["Location"]}
    print("Updating account...")
    _ua_result, _ua_code, _ua_headers = send_signed_request(acct_headers["Location"], {"contact": ["mailto:{}".format(email)]}, nonce_url, auth, account_key, "Error updating account")
    print("Done")
    return auth

def request_challenges(ca_url, auth, domains, account_key):
    print("Making new order for {0}...".format(", ".join(list(domains))))
    identifier = {"identifiers": []}
    for domain in domains:
        identifier["identifiers"].append({"type": "dns", "value": domain})
    order, _order_code, order_headers = send_signed_request(get_directory(ca_url)["newOrder"], id, get_directory(ca_url)["newNonce"], auth, account_key, "Error creating new order")
    return order, order_headers

def dns_challenges(ca_url, auth, order, domain, thumbprint, account_key):
    challenges_info = []
    for auth_url in order["authorizations"]:
        authz_result, _authz_code, _authz_headers = send_signed_request(
            auth_url, None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting authorization")
        challenge = next((c for c in authz_result["challenges"] if c["type"] == "dns-01" and authz_result["identifier"]["value"] == domain), None)
        if challenge:
            token = challenge["token"]
            key_authorization = "{}.{}".format(token, thumbprint)
            chl_verification = b64(hashlib.sha256(key_authorization.encode()).digest())
            txt_rec = "_acme-challenge.{}".format(domain)
            txt_value = chl_verification
            challenges_info.append((txt_rec, txt_value, challenge["url"]))
    return challenges_info

def dns_verification(ca_url, auth, challenge_url, account_key):
    print("Requesting verification for {}...".format(challenge_url))
    verification_result, verification_code, _verification_headers = send_signed_request(
        challenge_url, {}, get_directory(ca_url)["newNonce"], auth, account_key, "Error submitting challenge")
    if verification_code != 200:
        print(f"Error submitting challenge:\nUrl: {challenge_url}\nData: {json.dumps(verification_result)}\nResponse Code: {verification_code}\nResponse: {verification_result}")
        return False
    print("Challenge verified for {}!".format(challenge_url))
    return True

def finalize_order(ca_url, auth, order_headers, csr, account_key):
    print("Waiting for challenges to pass...")
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status")
    print(f"Order status: {order['status']}")
    if order["status"] == "valid":
        print("Order is already valid. No need to finalize again.")
        return None
    if order["status"] != "ready":
        raise ValueError("Order status is not ready for finalization")
    print("Passed challenges!")
    print("Getting certificate...")
    csr_der = csr_to_der(csr)
    _fnlz_resp, fnlz_code, _fnlz_headers = send_signed_request(order["finalize"], {"csr": b64(csr_der)}, get_directory(ca_url)["newNonce"], auth, account_key, "Error finalizing order")
    if fnlz_code != 200:
        raise ValueError("Failed to finalize the order")
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status after finalization")
    if order["status"] == "valid":
        print("Order finalized successfully!")
    else:
        raise ValueError("Order finalization failed")
    cert_resp, cert_code, _cert_headers = send_signed_request(order["certificate"], None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting certificate")
    if cert_code != 200:
        raise ValueError("Failed to get the certificate")
    print("Received certificate!")
    return cert_resp

def get_txt(temp_pvt_file, csr_file, server, email):
    _common_name, _organization, _organizational_unit, _city_locality, _state_province, _country, domain_names_list, _signature_algorithm, _key_algorithm, _key_size = parse_csr(csr_file)
    auth = register_account(server, temp_pvt_file, email)
    order, order_headers = request_challenges(server, auth, domain_names_list, temp_pvt_file)
    txt_recs = []
    txt_values = []
    thumbprint = b64(hashlib.sha256(json.dumps(get_public_key(temp_pvt_file), sort_keys=True, separators=(',', ':')).encode()).digest())
    challenges_info = []
    for domain in domain_names_list:
        challenges = dns_challenges(server, auth, order, domain, thumbprint, temp_pvt_file)
        challenges_info.extend(challenges)
    for txt_rec, txt_value, challenge_url in challenges_info:
        txt_recs.append(txt_rec)
        txt_values.append(txt_value)
    return challenges_info, auth, order, order_headers, txt_recs, txt_values

def get_cert(temp_pvt_file, csr_file, challenges_info, auth, order_headers, server, email):
    for txt_rec, txt_value, challenge_url in challenges_info:
        success = check_txt_records(txt_rec, txt_value)
        if not success:
            print("DNS verification failed for {}. Exiting.".format(txt_rec))
            return None, None
        dns_success = dns_verification(server, auth, challenge_url, temp_pvt_file)
        if not dns_success:
            print("DNS verification failed for {}. Exiting.".format(challenge_url))
            return None, None
        else:
            print(f"DNS verification successful for {challenge_url}")
    cert = finalize_order(server, auth, order_headers, csr_file, temp_pvt_file)
    if cert:
        cert_file = write_file(cert, email)
    return cert_file
