import hashlib, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()
mallory = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
def ver(pk, sig, m):
    try: pk.verify(sig, m, pad, hashes.SHA256()); return "VALID"
    except InvalidSignature: return "INVALID"
msg = b"Pay Bob $100"
sig = priv.sign(msg, pad, hashes.SHA256())
print("public numbers n bits", pub.public_numbers().n.bit_length(), "e", pub.public_numbers().e)
print("sig bytes", len(sig), sig.hex()[:32])
print("verify original", ver(pub, sig, msg))
print("verify w/ Mallory key", ver(mallory, sig, msg))
for label, m in [("$100->$900", b"Pay Bob $900"), ("extra space", b"Pay Bob $100 "), ("bit flip", bytes([msg[0]^1])+msg[1:])]:
    print(label, ver(pub, sig, m))
h1=int.from_bytes(hashlib.sha256(msg).digest(),'big'); h2=int.from_bytes(hashlib.sha256(b"Pay Bob $900").digest(),'big')
print(hashlib.sha256(msg).hexdigest()[:16], hashlib.sha256(b"Pay Bob $900").hexdigest()[:16])
print("bits differing", bin(h1^h2).count("1"), "/256")
