import os
import sys
import time
from dnsCF import add_txt, del_txt
from genRecords import gen_cname, txt_recs
from genPrivCSR import gen_verify_pvt_csr
from LE_SignCSR import get_txt, get_cert
from tools import read_file

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

def check_cert(file_path):
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

def generate_ssl(i_domains, email, key_type, server):
    output_file = f"{email.split("@")[0]}/{email.split("@")[0]}_log.txt"
    with open(output_file, 'w') as f:
        sys.stdout = f
        print(f"SSL Certificate Generation Log for {email.split('@')[0]}\n")
    with open(output_file, 'a') as f:
        sys.stdout = f
        print("##### Generating DNS Records & Creating Private Key and Domain CSR #####\n")
        cf_domain = "silerudaagartha.eu.org"
        server = choose_ca_server(server)
        domains = get_domains(i_domains)
        exchange = extract_subdomains(domains)
        cname_recs, cname_values = gen_cname(domains, cf_domain, exchange)
        for cname_rec, cname_value in zip(cname_recs, cname_values):
            print(f"{cname_rec} ==> {cname_value}")
        pvt_file, csr_file, temppvt_file = gen_verify_pvt_csr(email, domains, key_type)
    with open(output_file, 'a') as f:
        sys.stdout = f
        print(f"##### Retrieving DNS01 Challenges from {server} #####\n")
        challenges_info, auth, _order, order_headers, _acme_txt_recs, _acme_txt_values = get_txt(temppvt_file, csr_file, server, email)
        try:
            for txt_records, _acme_txt_values, _ in challenges_info:
                txt_rec = txt_recs(txt_records, exchange)
                del_txt(txt_rec)
            print("TXT records deleted successfully")
        except Exception as e:
            print(f"Error deleting TXT records or no TXT records exists: {e}")
        for txt_records, acme_txt_values, _ in challenges_info:
            txt_rec = txt_recs(txt_records, exchange)
            print(f"Adding TXT records {txt_rec} with value {acme_txt_values} to CF DNS...")
            add_txt(txt_rec, acme_txt_values, email)
        for i in range(60):
            print(f"Waiting for DNS records to propagate... {60-i}", end="\r")
            time.sleep(1)
    with open(output_file, 'a') as f:
        sys.stdout = f
        print(f"##### Verifing DNS01 Challenges with {server} #####\n")
        while True:
            crt_file = get_cert(temppvt_file, csr_file, challenges_info, auth, order_headers, server, email)
            if check_cert(crt_file) == True:
                break
            else:
                time.sleep(20)
        try:
            for txt_records, acme_txt_values, _ in challenges_info:
                txt_rec = txt_recs(txt_records, exchange)
                del_txt(txt_rec)
            print("TXT records deleted successfully")
        except Exception as e:
            print(f"Error deleting TXT records: {e}")
    with open(output_file, 'a') as f:
        sys.stdout = f
        print("##### SSL Certificates Generated Successfully #####\n")
        os.remove(f"{email.split('@')[0]}/tempPrivate.pem")
        os.remove(f"{email.split('@')[0]}/public.pem")
    return pvt_file, csr_file, crt_file, output_file
        
def main(i_domains, email, key_type, server):
    generate_ssl(i_domains, email, key_type, server)
    path = email.split('@')[0]
    pvt_file = os.path.join(path, "private.pem")
    csr_file = os.path.join(path, "domain.csr")
    crt_file = os.path.join(path, "certificate.pem")
    output_file = os.path.join(path, f"{path}_log.txt")
    if os.path.exists(pvt_file) and os.path.exists(csr_file) and os.path.exists(crt_file) and os.path.exists(output_file):
        print(f"Private Key File: {pvt_file}")
        print(f"CSR File: {csr_file}")
        print(f"Certificate File: {crt_file}")
        print(f"SSL Generation Log File: {output_file}")
        return pvt_file, csr_file, crt_file, output_file
    elif os.path.exists(output_file):
        error = "Error generating SSL Certificate. Please check the logs for more details."
        return error, error, error, output_file
    else:
        contact_us = "Error generating Console Log. Please contact us."
        return contact_us, contact_us, contact_us, contact_us

if __name__ == "__main__":
    i_domains = "thenayankasturi.eu.org, www.thenayankasturi.eu.org, dash.thenayankasturi.eu.org"
    email = "raannakasturi@gmail.com"
    key_type = "rsa4096" # ec256 or ec384 or rsa2048 or rsa4096
    server = "letsencrypt" # letsencrypt or letsencrypt_test or buypass or buypass_test or zerossl or sslcomRSA or sslcomECC or google or googletest
    pvt, csr, crt, log = main(i_domains, email, key_type, server)
    print(f"Private Key:\n{read_file(pvt)}")
    print(f"CSR:\n{read_file(csr)}")
    print(f"Certificate:\n{read_file(crt)}")
    print(f"Log:\n{read_file(log)}")