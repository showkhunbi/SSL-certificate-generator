from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
import time

from acme import client
from acme import messages
import josepy


# DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'
DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
KEY_SIZE = 2048


def get_http_challenge(authzr):
    for challenge in authzr.body.challenges:
        if challenge.chall.typ == 'http-01':
            return challenge
    else:
        raise Exception("Could not find an HTTP challenge!")


def request_cert(domain):
    domain = domain.lower()
  
    print("Generating user key")
    user_key = josepy.JWKRSA(
        key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
    )

    client_network = client.ClientNetwork(user_key)
    print(client_network)

    print("Connecting to Let's Encrypt on {}".format(DIRECTORY_URL))
    acme = client.ClientV2(DIRECTORY_URL, client_network)
    print("Registering")

    new_account = messages.NewRegistration()
    print(new_account)
    regr = acme.new_account(new_account)
    print("Agreeing to ToS")
    acme.agree_to_tos(regr)

    print("Requesting challenges")
    authzr = acme.request_challenges(
        identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain)
    )

    print("Looking for HTTP challenge")
    challenge = get_http_challenge(authzr)

    print("You need to set up the challenge response.")
    print("URL: http://{}{}".format(domain, challenge.chall.path))
    print("Content: {}".format(challenge.chall.validation(user_key)))

    response = challenge.chall.response(user_key)
    while not response.simple_verify(challenge.chall, domain, user_key.public_key()):
        input("It doesn't look like it's set up yet; press return when it is.")

    print("Authorizing -- here goes...")
    auth_response = acme.answer_challenge(challenge, challenge.chall.response(user_key))
    print("Response was {}".format(auth_response))

    print("Waiting for authorization to become valid")
    while True:
        print("Polling")
        authzr, authzr_response = acme.poll(authzr)
        challenge = get_http_challenge(authzr)
        if challenge.status.name == "valid":
            break
        print("HTTP challenge is currently {}".format(challenge))
        time.sleep(1)
    print("Auth valid")

    print("Generating CSR")
    certificate_key = crypto.PKey()
    certificate_key.generate_key(crypto.TYPE_RSA, 2048)
    csr = crypto.X509Req()
    csr.get_subject().CN = domain
    csr.set_pubkey(certificate_key)
    csr.sign(certificate_key, "sha256")

    print("Requesting certificate")
    certificate_response = acme.request_issuance(josepy.util.ComparableX509(csr), [authzr])
    print("Got it!")

    print("Fetching chain")
    chain = acme.fetch_chain(certificate_response)
    print("Done!")

    print("Here are the details:")

    print("Private key:")
    print(crypto.dump_privatekey(FILETYPE_PEM, certificate_key))

    print("Combined cert:")
    print(crypto.dump_certificate(FILETYPE_PEM, certificate_response.body.wrapped))
    for cert in chain:
        print(crypto.dump_certificate(FILETYPE_PEM, cert.wrapped))
       

request_cert("butopia.com.ng")