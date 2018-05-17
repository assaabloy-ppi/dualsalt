# dualsalt
Extension to NaCl crypto library to handling dual-signing (two-part singning) and dual-decryption (two-part decryption).

Disclaimer

We take no responsibility for the reliability or security of this library. Use at your own risk.

Design decisions
- The library dose not use x25519 as TweetNaCl uses. This is for two reasons for this.
Minimizing the amount of functions dependent on in TweetNaCl
Enabling the possibility to use the same long term key for both signing and decryption. (Common is to separate
this two for security reasons)
- The secret key used in TweetNaCl is stored always stored with the public key. We do not do that anymore
The secret key is then hashed on usage to get a scalar part and a rand seed to the r creation in signing.
To enable rotateKey() the secret key is now stored after the hashing with makes it bigger. So a secret key
is still 64 bytes
- We limited the lib to just handel 2 of 2 signing and decryption even if it easy could have benn made
for 3 of 3 etc. The reason for this is simplicity and that we came to the conclusion that 2 of 2 handles most
the use cases we could throw at it.
- The code is not written to pure JAVA standards but has a more C-ish feel to it with static functions and byte
arrays tossed around. This is course the code sooner or later shall bee ported to other languages and the be
easy to compare between each other. Another reason is to stay more close to the original TweetNaCl code
by Daniel J. Bernstein, Tanja Lange, Peter Schwabe.
- No real effort has been done to optimize the library for speed. At multiple locations the use of subroutines
makes so that parameters are packed and then unpacked (quite time consuming) but this has heighten the
readability of the code. The devices that we see using this library will not have any high recuirements.
Optimizations can always be done later on if the need occur.

Thanks to
- InstantWebP2P/tweetnacl-java that is the implementation of TweetNaCl that DualSalt uses as foundation.

Example

    byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
    byte[] secKeyA = new byte[DualSalt.secretKeyLength];
    DualSalt.createKeyPair(pubKeyA, secKeyA, random(32));
    
    byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
    byte[] secKeyB = new byte[DualSalt.secretKeyLength];
    DualSalt.createKeyPair(pubKeyB, secKeyB, random(32));
    
    // Calculate a virtual key
    byte[] virtualPublicKey = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
    
    // Sign for the virtual key with the two key pairs
    byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
    byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB);
    byte[] signature = DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);
    DualSalt.signVerify(signature, virtualPublicKey)
    
    // Decrypt data encrypted for the virtual key with the two key pairs
    byte[] cipherMessage = DualSalt.encrypt(message, nonce, virtualPublicKey, random(32));
    byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
    byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, nonce, secKeyB);
    message == decryptedMessage
    
    // Rotate the two keypairs but the are still represented by the virtual key
    byte[] random = random(32)
    DualSalt.rotateKey(pubKeyA, secKeyA, random, true);
    DualSalt.rotateKey(pubKeyB, secKeyB, random, false);
    
    // Sign for the virtual key with the two new key pairs
    m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
    m2 = DualSalt.signCreateDual2(m1, secKeyB);
    signature = DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);
    DualSalt.signVerify(signature, virtualPublicKey)
    
    // Decrypt data encrypted for the virtual key with the two new key pairs
    cipherMessage = DualSalt.encrypt(message, nonce, virtualPublicKey, random(32));
    d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
    decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, nonce, secKeyB);
    message == decryptedMessage
