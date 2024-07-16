from jwcrypto import jwk
import binascii

def get_public_key(account_key):
    print("Decoding private key...")
    
    # Load the private key from the file
    with open(account_key, "r") as f:
        private_key_pem = f.read()
    
    # Create a JWK object from the private key
    private_key = jwk.JWK.from_pem(private_key_pem.encode())
    print(private_key, "\n___________________________")
    
    # Export the private key to a dictionary
    private_key_dict = private_key.export()
    print(private_key_dict, "\n___________________________")
    
    # Extract the public key parameters
    pub_mod64 = private_key_dict["n"]
    pub_exp64 = private_key_dict["e"]
    
    # Create the JWK object for the public key
    public_key = {"e": pub_exp64, "kty": "RSA", "n": pub_mod64}
    
    print("Found public key!")
    return public_key

if __name__ == "__main__":
    account_key = "admin/tempPrivate.pem"
    get_public_key(account_key)