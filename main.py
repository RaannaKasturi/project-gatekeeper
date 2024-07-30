import os
import time
from dnsCF import add_txt, del_txt
from genRecords import gen_cname, txt_recs
from genPrivCSR import gen_verify_pvt_csr
from LE_SignCSR import get_txt, get_cert

def get_domains(i_domains):
    domains = []
    for domain in i_domains.split(","):
        domain = domain.strip()
        domains.append(domain)
    return domains

def choose_ca_server(provider):
    if provider == "letsencrypt":
        return "https://acme-v02.api.letsencrypt.org/directory"
    elif provider == "letsencrypt_test":
        return "https://acme-staging-v02.api.letsencrypt.org/directory"
    elif provider == "buypass":
        return "https://api.buypass.com/acme/directory"
    elif provider == "buypass_test":
        return "https://api.test4.buypass.no/acme/directory"
    elif provider == "zerossl":
        return "https://acme.zerossl.com/v2/DV90"
    elif provider == "sslcomRSA":
        return "https://acme.ssl.com/sslcom-dv-rsa"
    elif provider == "sslcomECC":
        return "https://acme.ssl.com/sslcom-dv-ecc"
    elif provider == "google":
        return "https://dv.acme-v02.api.pki.goog/directory"
    elif provider == "googletest":
        return "https://dv.acme-v02.test-api.pki.goog/directory"
    else:
        print("Invalid provider.")
        return None
    
def extract_subdomains(domains):
    exchange = min(domains, key=len)
    return exchange

def checkc_cert(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            if content:
                return True
            else:
                return False
    except (FileNotFoundError, IsADirectoryError) as e:
        print(f"Error opening file: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

if __name__ == "__main__":
    i_domains = "thenayankasturi.eu.org, www.thenayankasturi.eu.org, dash.thenayankasturi.eu.org"
    email = "raannakasturi@gmail.com"
    keyType = "rsa2048" # ec256 or ec384 or rsa2048 or rsa4096
    cfDomain = "silerudaagartha.eu.org"
    server = choose_ca_server("letsencrypt_test")
    domains = get_domains(i_domains)
    exchange = extract_subdomains(domains)
    CNAMERecs, CNAMEValues = gen_cname(domains, cfDomain, exchange)
    for CNAMERec, CNAMEValue in zip(CNAMERecs, CNAMEValues):
        print(f"{CNAMERec} ==> {CNAMEValue}")
    privFile, csrFile, tempPrivFile = gen_verify_pvt_csr(email, domains, keyType)
    challenges_info, auth, order, order_headers, acmeTXTRecs, acmeTXTValues = get_txt(tempPrivFile, csrFile, server, email)
    try:
        for txtRecords, acmeTXTValues, _ in challenges_info:
            TXTRRec = txt_recs(txtRecords, exchange)
            del_txt(TXTRRec)
        print("TXT records deleted successfully")
    except Exception as e:
        print(f"Error deleting TXT records or no TXT records exists: {e}")
    for txtRecords, acmeTXTValues, _ in challenges_info:
        TXTRRec = txt_recs(txtRecords, exchange)
        print(f"Adding TXT records {TXTRRec} with value {acmeTXTValues} to CF DNS...")
        add_txt(TXTRRec, acmeTXTValues, email)
    for i in range(60):
        print(f"Waiting for DNS records to propagate... {60-i}", end="\r")
        time.sleep(1)
    while True:
        certFile = get_cert(tempPrivFile, csrFile, challenges_info, auth, order_headers, server, email)
        if checkc_cert(certFile) == True:
            break
        else:
            time.sleep(20)
    try:
        for txtRecords, acmeTXTValues, _ in challenges_info:
            TXTRRec = txt_recs(txtRecords, exchange)
            del_txt(TXTRRec)
        print("TXT records deleted successfully")
    except Exception as e:
        print(f"Error deleting TXT records: {e}")
    os.remove(f"{email.split('@')[0]}/tempPrivate.pem")
    os.remove(f"{email.split('@')[0]}/domain.csr")
    os.remove(f"{email.split('@')[0]}/public.pem")
    print("Private Key: ", privFile)
    print("Certificate: ", certFile)