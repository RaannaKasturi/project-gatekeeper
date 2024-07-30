import binascii
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def gen_jwk(account_key):
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
    temp_jwk = {
        "e": base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8'),
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8')
    }
    jwk = json.dumps(temp_jwk)
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
        domain_names.add('N/A')
    domains = sorted(domain_names)
    public_key = csr.public_key()
    key_type = public_key.__class__.__name__
    size = public_key.key_size
    common_name = components.get('commonName', 'N/A')
    organization = components.get('organizationName', 'N/A')
    organizational_unit = components.get('organizationalUnitName', 'N/A')
    city_locality = components.get('localityName', 'N/A')
    state_province = components.get('stateOrProvinceName', 'N/A')
    country = components.get('countryName', 'N/A')
    domain_names_list = domains
    signature_algorithm = csr.signature_algorithm_oid._name
    key_algorithm = key_type
    key_size = size
    return common_name, organization, organizational_unit, city_locality, state_province, country, domain_names_list, signature_algorithm, key_algorithm, key_size

def csr_to_der(csr):
    csr_file = csr
    with open(csr_file, 'rb') as f:
        csr_pem = f.read()
    csr_data = x509.load_pem_x509_csr(csr_pem, default_backend())
    csr_der = csr_data.public_bytes(encoding=serialization.Encoding.DER)
    return csr_der
