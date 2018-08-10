
Do not use! Broken!
===================
See issue #11

DualSalt
========

DualSalt is an extension to the NaCl crypto library. It handles dual-signing (two-party signing) and 
dual-decryption (two-party decryption).



Dependencies
============

No dependencies on other libraries. Only Java 7 (or later) is needed.



Code example
============

The code below shows how two parties, A, and B, together can create a virtual key pair (virtualKeyPair),
and together use it to sign 'message'.

The example also shows how anyone who has the virtual public key can encrypt for the A-B pair
and how A-B together can decrypt such a message.

Finally, the example show how A's and B's secret data can be rotated while preserving 
there ability to represent the same virtual key pair.

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
    byte[] cipherMessage = DualSalt.encrypt(message, virtualPublicKey, random(32));
    byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
    byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, secKeyB);
    message == decryptedMessage
    
    // Rotate the two keypairs, but they still represent the same virtual key pair.
    byte[] random = random(32)
    DualSalt.rotateKey(pubKeyA, secKeyA, random, true);
    DualSalt.rotateKey(pubKeyB, secKeyB, random, false);
    
    // Sign for the virtual key with the two new key pairs
    m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
    m2 = DualSalt.signCreateDual2(m1, secKeyB);
    signature = DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);
    DualSalt.signVerify(signature, virtualPublicKey);
    
    // Decrypt data encrypted for the virtual key with the two new key pairs
    cipherMessage = DualSalt.encrypt(message, virtualPublicKey, random(32));
    d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
    decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, secKeyB);
    message == decryptedMessage;



Design decisions
================

- The library does not use x25519 for encryption as TweetNaCl uses. Instead it uses Ed25519 for both signing and encryption. There are two reasons for this.
  - Minimizing the amount of function dependencies to TweetNaCl
  - Enabling the possibility to use the same long term key for both signing and decryption. (Common is to separate
these two for security reasons)
  - Doing group element addition (public key) on x25519 is tricky because the y coordinate is hard to recreate.
- The secret key used in TweetNaCl is always stored with the public key. This library does not do that. The secret key in TweetNaCl is hashed on usage to get a scalar and a rand seed to the r creation in signing. To enable rotateKey() in dualsalt the secret key is stored after the hashing which makes it longer resulting in a secret key that is still 64 bytes
- Dualsalt is limited to just handle 2 of 2 signing and decryption even if it easy could have been made for 3 of 3 etc. The reason for this is simplicity and the conclusion that 2 of 2 handles most of the use cases we could throw at it.
- The code is not written to pure JAVA standards and has a more C-ish feel to it with static functions and byte arrays that are tossed around. This is because the code sooner or later shall be ported to other languages and then the code comparing will be easier. Another reason is to stay closer to the original TweetNaCl code by Daniel J. Bernstein, Tanja Lange, Peter Schwabe.
- No real effort has been done to optimize the library for speed. At multiple locations the use of subroutines do so that parameters are packed and then unpacked (quite time consuming) but this has heighten the readability of the code. Optimizations can always be done later on if the need occurs.



Thanks to
=========

- InstantWebP2P/tweetnacl-java that is the implementation of TweetNaCl that DualSalt uses as foundation.


    
Disclaimer
==========

We take no responsibility for the reliability or security of this library. Use at your own risk.
    

    
Code conventions
================

The original Java code conventions, originally by Sun, is used and the following conventions
that take precedence.

* Max line width: 100 (not 80).
* Encoding: UTF-8 must be used. 
* "\n" is used for new line.



