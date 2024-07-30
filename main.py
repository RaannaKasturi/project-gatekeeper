

import os
import time
from dnsCF import addTXT, delTXT
from genRecords import genCNAME, TXTRec
from genPrivCSR import genPrivCSR
from LE_SignCSR import getTXT, getCert

def getDomains(iDomains):
    domains = []
    for domain in iDomains.split(","):
        domain = domain.strip()
        domains.append(domain)
    return domains

def chooseCAserver(provider):
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
    
def extractSubDomains(domains):
    exchange = min(domains, key=len)
    return exchange

def checkCert(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            if content:
                return True
            else:
                return False
    except:
        return False

if __name__ == "__main__":
    iDomains = "thenayankasturi.eu.org, www.thenayankasturi.eu.org, dash.thenayankasturi.eu.org"
    email = "raannakasturi@gmail.com"
    keyType = "rsa2048" # ec256 or ec384 or rsa2048 or rsa4096
    cfDomain = "silerudaagartha.eu.org"
    server = chooseCAserver("letsencrypt_test")
    domains = getDomains(iDomains)
    exchange = extractSubDomains(domains)
    CNAMERecs, CNAMEValues = genCNAME(domains, cfDomain, exchange)
    for CNAMERec, CNAMEValue in zip(CNAMERecs, CNAMEValues):
        print(f"{CNAMERec} ==> {CNAMEValue}")
    privFile, csrFile, tempPrivFile = genPrivCSR(email, domains, keyType)
    challenges_info, auth, order, order_headers, acmeTXTRecs, acmeTXTValues = getTXT(tempPrivFile, csrFile, server, email)
    try:
        for txtRecords, acmeTXTValues, _ in challenges_info:
            TXTRRec = TXTRec(txtRecords, exchange)
            delTXT(TXTRRec)
        print("TXT records deleted successfully")
    except:
        print("error deleting TXT records or no records to delete")
    for txtRecords, acmeTXTValues, _ in challenges_info:
        TXTRRec = TXTRec(txtRecords, exchange)
        print(f"Adding TXT records {TXTRRec} with value {acmeTXTValues} to CF DNS...")
        addTXT(TXTRRec, acmeTXTValues, email)
    for i in range(60):
        print(f"Waiting for DNS records to propagate... {60-i}", end="\r")
        time.sleep(1)
    while True:
        certFile = getCert(tempPrivFile, csrFile, challenges_info, auth, order, order_headers, server, email)
        if checkCert(certFile) == True:
            break
        else:
            time.sleep(20)
            continue
    try:
        for txtRecords, acmeTXTValues, _ in challenges_info:
            TXTRRec = TXTRec(txtRecords, exchange)
            delTXT(TXTRRec)
        print("TXT records deleted successfully")
    except:
        print("error deleting TXT records")
    os.remove(f"{email.split('@')[0]}/tempPrivate.pem")
    os.remove(f"{email.split('@')[0]}/domain.csr")
    os.remove(f"{email.split('@')[0]}/public.pem")
    print("Private Key: ", privFile)
    print("Certificate: ", certFile)