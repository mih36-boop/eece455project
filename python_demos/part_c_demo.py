"""Short Part C: real RSA-PSS and HMAC-SHA256 verification."""
import argparse
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

def verify(pub, signature, message):
    try:
        pub.verify(signature, message, PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False

def tag(key, message):
    return hmac.digest(key, message, 'sha256')

def check(key, message, value):
    return hmac.compare_digest(tag(key, message), value)

def status(value):
    return 'NO KEY' if value is None else 'VALID' if value else 'INVALID'

def run(context=None, live=False):
    if context is None:
        alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub, msg = alice.public_key(), b'Pay Bob $100'
        sig = alice.sign(msg, PSS, hashes.SHA256())
    else:
        pub, msg, sig = (context[k] for k in ('pub', 'msg', 'sig'))
    key = secrets.token_bytes(32)
    original_tag = tag(key, msg)
    bob = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = b'Pay Bob $10,000'
    bob_sig = bob.sign(forged, PSS, hashes.SHA256())
    baseline = (verify(pub, sig, msg), check(key, msg, original_tag))
    receiver = (verify(pub, bob_sig, forged), check(key, forged, tag(key, forged)))
    # Charlie has only the authentic public key; MAC verification is unavailable.
    third_party = (verify(pub, sig, msg), None)
    assert baseline == (True, True)
    assert receiver == (False, True)
    assert verify(bob.public_key(), bob_sig, forged)
    assert third_party == (True, None)
    print('\nPART C | RSA-PSS vs HMAC-SHA256')
    print('Original:', msg.decode())
    print('Bob claims Alice sent:', forged.decode())
    print('Charlie has only Alice\'s public key.\n')
    print(f'{"Experiment":<31} | {"RSA-PSS":<9} | HMAC')
    print('-' * 57)
    for label, pair in [('1. Original message', baseline), ('2. Bob impersonates Alice', receiver), ('3. Charlie verifies original', third_party)]:
        print(f'{label:<31} | {status(pair[0]):<9} | {status(pair[1])}')
    print('\nNO KEY = verification unavailable, not invalid.')
    print('Digital signatures separate signing and verification.')
    return baseline, receiver, third_party

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Accepted for compatibility; short demo has no internal pauses.')
    run(live=parser.parse_args().live)
