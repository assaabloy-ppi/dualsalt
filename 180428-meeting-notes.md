Notes from meeting 2018-04-228
==============================

Håkan Olsson, Frans Lundberg, ASSA ABLOY AB, Stockholm.

* Repo created. Called "dualsalt". Available at gibhub.com/assaabloy-ppi/dualsalt/.
* Open source, MIT licens. Work-in-progress directly to Github.
* Library limited to dual-signing (Ed25519) and dual-decryption.
* rotateKey() is the "limit" of what the library provides.
* Library uses only Ed25519 curve, for both signing *and* decryption. x25519 is not used.
* Dependency: https://github.com/InstantWebP2P/tweetnacl-java, Java implementation of NaCl.
* Dependency: Java 7 (must work with Android).


List of functions
=================

Preliminary, of course.

    sign
    signP1
    signP2
    signP3
    encrypt
    decrypt
    decryptP1
    decryptP2
    addPubKeys
    createKey
    rotateKey


Secret scalar format
====================

Format for storing the secret scalar as a byte array. Including 
random data used for signature creation. 
The secret scalar (explicitely) is needed for key rotation. The original
NaCl secret keys as seeds that a secret scalar can be computed from (via hashing).

    SECRET  FORMAT
         
    32   Scalar
             
         The secret scalar (field element). Stored as in NaCl as 32 bytes.
         
    32   Random
    
         32 random bytes.
         
Total 64 bytes.
