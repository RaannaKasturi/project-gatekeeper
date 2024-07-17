import asyncio
from acmetk.client import AcmeClient

dir = "https://dv.acme-v02.test-api.pki.goog/directory"
pvtkey = "private.pem"
mycontact = {'email': 'raannakasturi@gmail.com'}
kidy = "bwrL2j53xKY4O9e7B6Txk2vNY4F2IZ8tiA8fv3_bZuwwvfPTE3y5dIEsLr-R2xDGYEJ4Cx6122QWcknxOqx4cQ"
hmac = "da6f466d667da13ffe2b4eabd68c3daf"

async def main():
    client = AcmeClient(
       directory_url=dir,
       private_key=pvtkey,
       contact=mycontact
    )

    # Register the account using the kid and hmac_key
    account_info = await client.account_register(
        email=mycontact['email'],
        phone=None,
        kid=kidy,
        hmac_key=hmac
    )

    print(account_info)

asyncio.run(main())