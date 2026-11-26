
import argparse
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# Change these to try other messages. Set BOB_MESSAGE equal to ALICE_MESSAGE
# to see Bob forge the exact message Alice sent.
ALICE_MESSAGE = b'Pay Bob $100'
BOB_MESSAGE = b'Pay Bob $10,000'

def verify(pub, signature, message):
    try:
        pub.verify(signature, message, PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False
#helper fcts for authentication tag generation
def tag(key, message):
    return hmac.digest(key, message, 'sha256')

def check(key, message, value):
    return hmac.compare_digest(tag(key, message), value)

def status(value):
    return 'NO KEY' if value is None else 'VALID' if value else 'INVALID'

#if context = True, it would take alice's key from part a
def run(context=None, live=False, message=ALICE_MESSAGE, forged=BOB_MESSAGE):
    if context is None:
        alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub, msg = alice.public_key(), message
        sig = alice.sign(msg, PSS, hashes.SHA256())
    else:
        pub, msg, sig = (context[k] for k in ('pub', 'msg', 'sig'))
    key = secrets.token_bytes(32)
    original_tag = tag(key, msg) #alice generates her tag
    bob = rsa.generate_private_key(public_exponent=65537, key_size=2048) #bob generates his own rsa key pair
    same = forged == msg #if same =True, then bob's forged message is exactly the same as alice
    bob_sig = bob.sign(forged, PSS, hashes.SHA256())
    bob_tag = tag(key, forged)
    #experiment 1:
    baseline = (verify(pub, sig, msg), check(key, msg, original_tag)) 
    #experiment 2:
    receiver = (verify(pub, bob_sig, forged), check(key, forged, bob_tag))
    #experiment 3:
    third_party = (verify(pub, sig, msg), None)
    assert baseline == (True, True)
    assert receiver == (False, True)
    assert verify(bob.public_key(), bob_sig, forged)
    assert third_party == (True, None)
    assert hmac.compare_digest(bob_tag, original_tag) == same

    print('\nPART C | RSA-PSS vs HMAC-SHA256')
    print('Original:', msg.decode())
    print('Bob claims Alice sent:', forged.decode() + ('  (same as the original)' if same else ''))
    print('Charlie has only Alice\'s public key.\n')
    print(f'{"Experiment":<31} | {"RSA-PSS":<9} | HMAC')
    print('-' * 57)
    label2 = '2. Bob forges the same message' if same else '2. Bob impersonates Alice'
    for label, pair in [('1. Original message', baseline), (label2, receiver), ('3. Charlie verifies original', third_party)]:
        print(f'{label:<31} | {status(pair[0]):<9} | {status(pair[1])}')
    print('\nNO KEY = verification unavailable, not invalid.')
    if same:
        print('\nBob forged the exact message Alice sent:')
        print('  Alice\'s HMAC tag:', original_tag.hex())
        print('  Bob\'s HMAC tag:  ', bob_tag.hex())
        print('  The tags are identical (HMAC is deterministic), so no one can tell who made it.')
        print('  Bob\'s RSA signature still fails: only Alice\'s private key verifies under her public key.')
    print('Digital signatures separate signing and verification.')
    return baseline, receiver, third_party

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true', help='Accepted for compatibility; short demo has no internal pauses.')
    parser.add_argument('--message', default=ALICE_MESSAGE.decode(), help="Alice's original message.")
    parser.add_argument('--forged', default=BOB_MESSAGE.decode(), help="Bob's impersonation message (same text as --message forges Alice's exact message).")
    args = parser.parse_args()
    run(live=args.live, message=args.message.encode(), forged=args.forged.encode())
