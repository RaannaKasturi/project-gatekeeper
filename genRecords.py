import hashlib

def get_domains(iDomains):
    domains = []
    for domain in iDomains.split(","):
        domain = domain.strip()
        domains.append(domain)
    return domains

def prefix(domain):
    domain_bytes = domain.encode()
    prefix = hashlib.blake2b(domain_bytes, digest_size=12).hexdigest()
    return prefix

def gen_cname_recs(domains):
    CNAMERecs = []
    for domain in domains:
        CNAMERec = f"_acme-challenge.{domain}"
        CNAMERecs.append(CNAMERec)
    return CNAMERecs

def gen_cname_values(domains, cfDomain, exchange):
    tempCNAMEValues = []
    CNAMEValues = []
    for domain in domains:
        CNAMEValue = prefix(domain)
        CNAMEValue = f"{CNAMEValue}.{domain}"
        tempCNAMEValues.append(CNAMEValue)
    for CNAMEValue in tempCNAMEValues:
        modified_CNAMEValue = CNAMEValue.replace(exchange, cfDomain)
        CNAMEValues.append(modified_CNAMEValue)
    return CNAMEValues

def gen_cname(domains, cfDomain, exchange):
    records = []
    CNAMERecs  = gen_cname_recs(domains)
    CNAMEValues = gen_cname_values(domains, cfDomain, exchange)
    return CNAMERecs, CNAMEValues

def txt_recs(txtRecords, exchange):
    txtRecord = txtRecords.replace("_acme-challenge.", "")
    txtRec = txtRecord.replace(f"{exchange}", "")
    pre = prefix(txtRecord)
    rec = f"{pre}.{txtRec}"
    rec = rec.strip(".")
    return rec