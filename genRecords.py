import hashlib

def get_domains(i_domains):
    domains = []
    for domain in i_domains.split(","):
        domain = domain.strip()
        domains.append(domain)
    return domains

def prefix(domain):
    domain_bytes = domain.encode()
    prefix = hashlib.blake2b(domain_bytes, digest_size=12).hexdigest()
    return prefix

def gen_cname_recs(domains):
    cname_recs = []
    for domain in domains:
        cname_rec = f"_acme-challenge.{domain}"
        cname_recs.append(cname_rec)
    return cname_recs

def gen_cname_values(domains, cf_domain, exchange):
    temp_cname_values = []
    cname_values = []
    for domain in domains:
        cname_value = prefix(domain)
        cname_value = f"{cname_value}.{domain}"
        temp_cname_values.append(cname_value)
    for cname_value in temp_cname_values:
        modified_cname_Value = cname_value.replace(exchange, cf_domain)
        cname_values.append(modified_cname_Value)
    return cname_values

def gen_cname(domains, cf_domain, exchange):
    cname_recs  = gen_cname_recs(domains)
    cname_values = gen_cname_values(domains, cf_domain, exchange)
    return cname_recs, cname_values

def txt_recs(txt_records, exchange):
    txt_record = txt_records.replace("_acme-challenge.", "")
    txtRec = txt_record.replace(f"{exchange}", "")
    pre = prefix(txt_record)
    rec = f"{pre}.{txtRec}"
    rec = rec.strip(".")
    return rec