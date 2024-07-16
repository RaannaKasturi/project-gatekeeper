import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from OpenSSL import crypto

class InvalidKeyType(Exception):
    pass

def savefile(filename, data):
    with open(filename, 'wb') as f: 
        f.write(data)
    return filename

def generate_private_key(key_type):
    key = None
    private_key = None
    public_key = None

    if key_type == 'ec256':
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        public_key = key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    elif key_type == 'ec384':
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        public_key = key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    elif key_type == 'rsa2048':
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        public_key = key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    elif key_type == 'rsa4096':
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        public_key = key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    else:
        options = ['ec256', 'ec384', 'rsa2048', 'rsa4096']
        raise InvalidKeyType(f"Invalid private key type '{key_type}'. Options are {options}")

    return private_key, public_key

def genCSR(private_key, email, domains, common_name, country, state, locality, organization, organization_unit):
    sslDomains = [x509.DNSName(domain.strip()) for domain in domains]
    private_key_obj = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])
    
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sslDomains),
        critical=False,
    )
    csr = builder.sign(private_key_obj, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)

def verifyPrivCSR(privdata, csrdata):
    try:
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrdata)
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, privdata)
        req.verify(pkey)
        return True
    except crypto.Error:
        print("Private key and CSR verification failed", exc_info=True)
        return False

def genPrivCSR(email, domains, key_type, common_name="", country="IN", state="Maharashtra", locality="Mumbai", organization="", organization_unit="IT"):
    if email.split("@")[1] == "demo.com" or email.split("@")[1] == "example.com" or email.count("@") > 1 or email.count(".") < 1:
        print("Invalid email address")
        return None, None
    if any(domain.startswith("*.") for domain in domains):
        print("Wildcard domains are not supported")
        return None, None
    if key_type not in ['ec256', 'ec384', 'rsa2048', 'rsa4096']:
        key_type = "rsa4096"
    common_name = common_name or domains[0].split(',')[0]
    organization = organization or common_name.split(".")[0]
    path = email.split("@")[0]
    os.makedirs(path, exist_ok=True)
    tempPrivFile = f"{path}/tempPrivate.pem"
    privFile = f"{path}/private.pem"
    pubFile = f"{path}/public.pem"
    csrFile = f"{path}/domain.csr"
    privdata, pubdata = generate_private_key(key_type)
    tempPrivdata, _ = generate_private_key(key_type)
    savefile(tempPrivFile, tempPrivdata)
    savefile(privFile, privdata)
    savefile(pubFile, pubdata)
    csrdata = genCSR(privdata, email, domains, common_name, country, state, locality, organization, organization_unit)
    savefile(csrFile, csrdata)
    if verifyPrivCSR(privdata, csrdata):
        print("Private key and CSR are verified")
        return privFile, csrFile, tempPrivFile
    else:
        print("Error in generating Private Key and CSR. Please try again.")
        return None, None, None
