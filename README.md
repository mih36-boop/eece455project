# EECE 455 — Digital Signatures and Message Authentication

This project demonstrates how digital signatures provide message integrity and authentication, and how they differ from message authentication codes (MACs) in key ownership and verification authority. It includes two independent interactive browser demos and their Python terminal counterparts. All cryptographic verification operations are real; the website uses the browser's Web Crypto API, not precomputed results.

## Part A — Digital Signature Generation and Verification

Alice generates an RSA-2048 key pair with public exponent 65537 and signs the message `Pay Bob $100` using RSA-PSS with SHA-256. SHA-256 produces a 256-bit message digest; PSS encodes it using a random salt and MGF1 before the RSA private-key operation generates a 256-byte signature. Verification uses Alice's public key and the received message to check the signature without requiring her private key.

The demo retains the original signature and performs five verification tests:

| Experiment | Expected result | Explanation |
|---|---|---|
| Original message | VALID | The message, signature and public key correspond. |
| Mallory's public key | INVALID | Mallory's unrelated public key cannot authenticate Alice's signature. |
| Modified payment: $100 to $900 | INVALID | The original signature no longer matches the message. |
| Additional trailing space | INVALID | Even a small change in the message bytes invalidates the original signature. |
| Bit flip | INVALID | Flipping the least significant bit of the first byte changes the signed message. |

The demo also illustrates the **SHA-256 avalanche effect** by hashing the original and modified messages, comparing their digests bit by bit and displaying the number of differing bits out of 256. With the default payment messages, 120 bits differ. This illustrates sensitivity to changes in input, rather than proving the security of SHA-256.

**Key takeaway:** A digital signature binds a message to the signing key and detects unauthorized modifications. Attribution to Alice assumes that her public key is authentic and her private key remains secure.

## Part C — Digital Signatures vs. MACs

This demo compares RSA-PSS and HMAC-SHA256 using three participants:

- **Alice:** Owns her RSA private key and shares an HMAC secret with Bob.
- **Bob:** Owns a separate RSA key pair and knows the same HMAC secret as Alice.
- **Charlie:** An independent third party who has Alice's authentic public key but does not know the HMAC secret.

### Cryptographic mechanisms

| Property | RSA-PSS | HMAC-SHA256 |
|---|---|---|
| Key type | Asymmetric | Symmetric |
| Generation | Private key | Shared secret |
| Verification | Public key | Same shared secret |
| Parameters in this demo | RSA-2048, SHA-256, MGF1, 222-byte salt | 256-bit shared secret, SHA-256 |
| Output size | 256-byte signature | 32-byte authentication tag |
| Generation behavior | Randomized | Deterministic for a fixed key and message |

HMAC performs inner and outer keyed hashing. The verifier uses the shared secret to recompute the authentication tag and compare it with the received tag. Unlike RSA-PSS, this gives the verifier the same tag-generation capability as the sender.

### Experiments

| Experiment | RSA-PSS | HMAC-SHA256 |
|---|---|---|
| 1. Original message | VALID | VALID |
| 2. Bob impersonates Alice | INVALID | VALID |
| 3. Charlie verifies the original | VALID | NO KEY |

**Experiment 1 — Original message.** Alice authenticates `Pay Bob $100` using her private signing key and the shared HMAC secret. Both verification operations succeed, establishing a baseline.

**Experiment 2 — Receiver impersonation.** Bob creates `Pay Bob $10,000` and claims that Alice sent it. He signs it using his own RSA private key and generates a new HMAC tag using the shared secret. Verification of Bob's signature under Alice's public key fails, but the new HMAC tag verifies successfully. As a control, Bob's signature is also verified with his own public key, which succeeds. Bob is not breaking HMAC: he is exercising the generation authority that comes with knowing the shared secret.

**Experiment 3 — Independent verification.** Charlie verifies Alice's original signature using her public key, the message and the signature. He cannot independently verify the HMAC without the shared secret. `NO KEY` explicitly represents an unavailable verification operation, not a failed cryptographic check. Giving Charlie the secret would also give him the ability to generate valid tags.

**Key takeaway:** Both mechanisms provide integrity and authentication, but only digital signatures separate signing authority from verification authority. Digital signatures therefore support independent verification and non-repudiation, subject to authentic public keys and secure private-key ownership. HMAC cannot distinguish between holders of the same secret in a dispute. Neither mechanism provides confidentiality by itself.

## Run the website

From the repository root:

```bash
python -m http.server 8000
```

Open [http://localhost:8000](http://localhost:8000) in a modern browser. Select Part A or Part C, then run the corresponding demo. Messages can be edited and fresh keys are generated on each run. The expected results above assume the default distinct payment messages. No Python packages, ChatGPT account or external API key are needed for the website. Web Crypto requires a supported secure context such as localhost or HTTPS.

## Run the Python demos

```bash
cd python_demos
python -m pip install -r requirements.txt
python part_a_demo.py
python part_c_demo.py
```

The optional `combined_demo.py` runs both terminal demonstrations. Python and browser implementations use separate keys and do not exchange data.

## Project structure

```text
digital-signatures-demo/
├── index.html                 # Browser interface with separate demo views
├── styles.css                 # Website styling
├── script.js                  # Real browser crypto: runA(), runC(), sign(), verify(), tag(), check()
├── README.md                  # Project documentation
├── .nojekyll                  # Intentionally empty GitHub Pages marker
└── python_demos/
    ├── part_a_demo.py         # RSA-PSS and avalanche effect
    ├── part_c_demo.py         # RSA-PSS vs. HMAC experiments
    ├── combined_demo.py       # Optional combined terminal demo
    └── requirements.txt       # Python dependencies
```

## GitHub Pages deployment

Push the repository contents to GitHub. Under **Settings → Pages**, select **Deploy from a branch**, choose `main` and `/(root)`, and save. Open the published HTTPS URL. GitHub Pages serves the HTML, CSS and JavaScript; it does not execute the Python scripts.

## Scope and reference

This is an educational demonstration, not a production payment or authentication system. Participant roles and key access are modeled within a single program; secure key distribution, certificates, replay prevention and real network communication are outside its scope.

Stallings, W. (2017). *Cryptography and network security: Principles and practice* (7th ed., Global ed.). Pearson. Sections 12.5 (HMAC), 13.1 (Digital Signatures), and 13.6 (RSA-PSS).
