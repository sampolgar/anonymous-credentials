# multi-use anonymous credential scheme in rust

rust-crypto or ring that provide cryptographic primitives.

keygen(): This function would be used by the issuer to generate a public-private key pair. The private key would be used to sign credentials, and the public key would be distributed publicly and used to verify signatures.

createCommitment(attrs): This function would take in a list of attributes and generate a commitment from them. The specifics of this function would depend on what commitment scheme you're using. A simple commitment scheme might involve hashing the attributes together with some random values, but more advanced schemes could use other cryptographic primitives.

createZKP(commitment, statement): This function would take in a commitment and a statement about the attributes ("I am over 18"), and create a zero-knowledge proof that the statement is true with respect to the commitment. The specifics would depend on the zero-knowledge proof protocol you're using.

sign(commitment): This function would be used by the issuer to sign the commitment. It would take in the commitment and the issuer's private key and output a signature. The signature scheme used can vary - it might be RSA, ECDSA, or something else.

randomizeSignature(signature): This function would take in a signature and output a randomized version of it. This might involve, for example, multiplying the signature by a random value raised to the power of the issuer's public key (for an RSA signature), but the specifics will depend on the signature scheme.

verifyZKP(proof, statement, public_key, randomized_signature): This function would take in a zero-knowledge proof, the statement being proven, the issuer's public key, and the randomized signature, and verify that the proof is valid. The verifier doesn't need to know the commitment or the original attributes.

selectiveDisclosure(proof, statement, public_key, randomized_signature, disclosed_attrs): This is an extended version of the verifyZKP function, which allows for selective disclosure of certain attributes. It would take in an additional argument which is a list of disclosed attributes and checks that they match the disclosed parts of the proof.
