import time
import simple_acme_dns



client = simple_acme_dns.ACMEClient(
    domains=["thenayankasturi.eu.org", "www.thenayankasturi.eu.org", "dash.thenayankasturi.eu.org"],
    email="raannakasturi@gmail.com",
    directory="https://dv.acme-v02.test-api.pki.goog/directory", #"https://acme-staging-v02.api.letsencrypt.org/directory",
    nameservers=["8.8.8.8", "1.1.1.1"],
    new_account=True,
    generate_csr=True
)
client.new_account()
pvt,  csr = client.generate_private_key_and_csr(key_type="rsa2048") # ec256, ec384, rsa2048, rsa4096
print(pvt)
print("---------------------------------------------------")
print(csr)
token = client.request_verification_tokens()
print("---------------------------------------------------")
print(token)
inp = input("Enter the token: ")
if inp:
    print("---------------------------------------------------")
for i in range(60):
    print(f"Waiting for DNS Propagation... {60-i} seconds left", end="\r")
    time.sleep(1)
while True:
    client.nameservers = ["8.8.8.8", "1.1.1.1"]
    log = client.check_dns_propagation(
        timeout=180,
        interval=5,
        authoritative=False,
        round_robin=True,
        verbose=True,
        EAB_KID="bwrL2j53xKY4O9e7B6Txk2vNY4F2IZ8tiA8fv3_bZuwwvfPTE3y5dIEsLr-R2xDGYEJ4Cx6122QWcknxOqx4cQ",
        EAB_HMAC_KEY="da6f466d667da13ffe2b4eabd68c3daf"
    )
    print("---------------------------------------------------")
    print(log)
    print("DNS Propagation Successful")
    cert = client.request_certificate()
    print("---------------------------------------------------")
    print(cert)
    break

def savefile(data, filename):
    with open(filename) as f:
        f.write(data)
        return filename
    
savefile(pvt, "pvt.pem")
savefile(csr, "csr.pem")
savefile(cert, "cert.pem")
