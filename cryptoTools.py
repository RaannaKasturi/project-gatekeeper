import binascii
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def genJWK(account_key):
    private_key_file = account_key
    with open(private_key_file, "rb") as key_file:
        private_key_bytes = key_file.read()
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e
    modulus_hex = binascii.hexlify(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
    exponent_hex = binascii.hexlify(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
    private_key_details = f"RSA Private-Key: (2048 bit, 2 primes)\nmodulus:\n"
    for i in range(0, len(modulus_hex), 32):
        private_key_details += "    " + ":".join(modulus_hex[i:i + 32][j:j + 2] for j in range(0, len(modulus_hex[i:i + 32]), 2)) + "\n"
    private_key_details += f"publicExponent: {e} (0x{exponent_hex})\n"
    tempJWK = {
        "e": base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8'),
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8')
    }
    jwk = json.dumps(tempJWK)
    return jwk

def sign(account_key, data):
    with open(account_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def parse_csr(file_path):
    with open(file_path, 'rb') as csr_file:
        csr_data = csr_file.read()
    csr = x509.load_pem_x509_csr(csr_data, default_backend())
    subject = csr.subject
    components = {attr.oid._name: attr.value for attr in subject}
    domain_names = set()
    try:
        san_extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains = san_extension.value.get_values_for_type(x509.DNSName)
        for domain in domains:
            domain_names.add(domain)
    except x509.ExtensionNotFound:
        domain_names = {'N/A'}  # No SAN extension found
    domains = sorted(domain_names)
    public_key = csr.public_key()
    key_type = public_key.__class__.__name__
    key_size = public_key.key_size
    commonName = components.get('commonName', 'N/A')
    organization = components.get('organizationName', 'N/A')
    organizationalUnit = components.get('organizationalUnitName', 'N/A')
    cityLocality = components.get('localityName', 'N/A')
    stateProvince = components.get('stateOrProvinceName', 'N/A')
    country = components.get('countryName', 'N/A')
    domainNames = domains
    signatureAlgorithm = csr.signature_algorithm_oid._name
    keyAlgorithm = key_type
    keySize = key_size
    return commonName, organization, organizationalUnit, cityLocality, stateProvince, country, domainNames, signatureAlgorithm, keyAlgorithm, keySize

def csr2Der(csr):
    with open("raannakasturi/domain.csr", 'rb') as f:
        csr_pem = f.read()
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
    return csr_der
