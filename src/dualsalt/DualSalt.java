// Copyright (c) 2018 ASSA ABLOY AB

package dualsalt;

import java.util.Arrays;

/**
 * Crypto library that enable dual signing and decryption (2 of 2) without the secret keys never being in
 * the same device. It also has signatures that is compatible with TweetNaCl (EdDSA). The idea is that the
 * end device that validates a signature or encrypt a message dose not have to know that the the public key it
 * works on really is a addison of two public keys and that it in fact are two devices that represent that
 * public key.
 */
public class DualSalt {

    private static final int secretRandomLength = 32;

    private static final int hashLength = 64;

    public static final int secretKeyLength = TweetNaclFast.ScalarMult.scalarLength + secretRandomLength;

    public static final int publicKeyLength = TweetNaclFast.ScalarMult.groupElementLength;

    public static final int nonceLength = TweetNaclFast.Box.nonceLength;

    public static final int seedLength = TweetNaclFast.Signature.seedLength;

    private static final int signatureLength = TweetNaclFast.Signature.signatureLength;

    private static final int cipherMessageHeaderLength = nonceLength + publicKeyLength;

    private static final int m1HeaderLength = TweetNaclFast.ScalarMult.groupElementLength + publicKeyLength;

    private static final int m2Length = signatureLength;

    private static final int d1Length = TweetNaclFast.ScalarMult.groupElementLength;

    /**
     * Create key pair. The secret key is not compatible with Tweetnacl but the public key is compatible with tweetnacl
     * signing.
     * @param publicKey (out) The created key pairs public key
     * @param secretKey (out) The created key pairs secret key
     * @param random    Random data used to create the key pair
     */
    public static void createKeyPair(byte[] publicKey, byte[] secretKey, byte[] random) {
        if (publicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (secretKey.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");
        if (random.length != seedLength) throw new IllegalArgumentException("Random source has the wrong length");

        TweetNaclFast.crypto_hash(secretKey, random, 0, seedLength);
        secretKey[0] &= 248;
        secretKey[31] &= 127;
        secretKey[31] |= 64;
        byte[] tempPublicKey = calculatePublicKey(secretKey);

        System.arraycopy(tempPublicKey, 0, publicKey, 0, publicKeyLength);
    }

    /**
     * Calculate the public key from a secret key. Can be used to make any scalar to a group element representation
     * @param secretKey The secret key to calculate the public key from
     * @return Returns the public key
     */
    public static byte[] calculatePublicKey(byte[] secretKey) {
        if (secretKey.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] publicKey = new byte[publicKeyLength];
        long[][] p = createUnpackedGroupEl();
        TweetNaclFast.scalarbase(p, secretKey, 0);
        TweetNaclFast.pack(publicKey, p);
        return publicKey;
    }

    /**
     * This function is used to "rotate" the two secret keys used to build up a dual key (virtual key pair). The two
     * key pairs kan be changed in such a way that the addition of there two public keys still adds up to the same value.
     * Run rotateKey() on the first key pair with the parameter first sat to true and then run rotateKey() on the second
     * key pair with the param first set to false. Reuse the same data for parameter random both time.
     * Parameter random is recommended to be sent between devices in a encrypted channel with forward secrecy such as
     * saltChannel
     * ************************************************
     * createKeyPair(A, a, r1)
     * createKeyPair(B, b, r2)
     * C1 = addPublicKeys(A, B)
     * rotateKey(A, a, r3, true) <- Change A and a
     * rotateKey(B, b, r3, false) <- Change B and b
     * C1 == addPublicKeys(A, B)
     * ***********************************************
     * @param publicKey (out) The new public key after rotation
     * @param secretKey (in/out) The earlier secret key in and the resulting secret key out after rotation
     * @param random    Random for the scalar multiplication part. Reuse for both parts in a virtual key pair
     * @param first     Shall be different between the to parts of the virtual key pair
     */
    public static void rotateKey(byte[] publicKey, byte[] secretKey, byte[] random, boolean first) {
        if (publicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (secretKey.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");
        if (random.length != seedLength) throw new IllegalArgumentException("Random source has the wrong length");

        byte[] tempSecretKey = new byte[secretKeyLength];
        TweetNaclFast.crypto_hash(tempSecretKey, random, 0, seedLength);
        byte[] scalarDiff = Arrays.copyOfRange(tempSecretKey, 0, TweetNaclFast.ScalarMult.scalarLength);
        scalarDiff[0] &= 248;
        scalarDiff[31] &= 127;

        // To reviewer: The new scalar might not have the second highest bit set to true. This is the case in key creation.
        // It is set to true with "secretKey[31] |= 64;". The highest bit can also be set to
        // true even if it should be false "scalarDiff[31] &= 127;". Will this break security?
        byte[] newScalar;
        if (first) {
            newScalar = addScalars(secretKey, scalarDiff);
        } else {
            newScalar = subtractScalars(secretKey, scalarDiff);
        }

        byte[] randomDiff = Arrays.copyOfRange(tempSecretKey, TweetNaclFast.ScalarMult.scalarLength, secretKeyLength);
        byte[] oldRandom = Arrays.copyOfRange(secretKey, TweetNaclFast.ScalarMult.scalarLength, secretKeyLength);
        byte[] newRandom = addScalars(oldRandom, randomDiff);

        System.arraycopy(newScalar, 0, secretKey, 0, TweetNaclFast.ScalarMult.scalarLength);
        System.arraycopy(newRandom, 0, secretKey, TweetNaclFast.ScalarMult.scalarLength, secretRandomLength);
        byte[] tempPublicKey = calculatePublicKey(secretKey);
        System.arraycopy(tempPublicKey, 0, publicKey, 0, publicKeyLength);
    }

    /**
     * Add two scalar to each others
     * @param scalarA The first scalar
     * @param scalarB The second scalar
     * @return The result as a scalar
     */
    private static byte[] addScalars(byte[] scalarA, byte[] scalarB) {
        int i;
        byte[] scalar = new byte[TweetNaclFast.ScalarMult.scalarLength];
        long[] temp = new long[64];
        for (i = 0; i < 64; i++) temp[i] = 0;
        for (i = 0; i < 32; i++) temp[i] = (long) (scalarA[i] & 0xff);
        for (i = 0; i < 32; i++) temp[i] += (long) (scalarB[i] & 0xff);

        TweetNaclFast.modL(scalar, 0, temp);

        return scalar;
    }

    /**
     * Subtract one scalar from another
     * @param scalarA A scalar
     * @param scalarB The scalar that is subtracted from the other
     * @return The result as a scalar
     */
    private static byte[] subtractScalars(byte[] scalarA, byte[] scalarB) {
        int i;
        byte[] scalar = new byte[TweetNaclFast.ScalarMult.scalarLength];
        long[] temp = new long[64];
        for (i = 0; i < 64; i++) temp[i] = 0;
        for (i = 0; i < 32; i++) temp[i] = (long) (scalarA[i] & 0xff);
        for (i = 0; i < 32; i++) temp[i] -= (long) (scalarB[i] & 0xff);

        TweetNaclFast.modL(scalar, 0, temp);

        return scalar;
    }

    /**
     * Add two public keys to each others. A public key is a group element and this function is also used to add group element
     * @param publicKeyA The first public key
     * @param publicKeyB The second public key
     * @return The result as a public key
     */
    public static byte[] addPublicKeys(byte[] publicKeyA, byte[] publicKeyB) {
        long[][] a = unpack(publicKeyA);
        long[][] b = unpack(publicKeyB);

        TweetNaclFast.add(a, b);

        byte[] publicKeyAB = new byte[publicKeyLength];
        TweetNaclFast.pack(publicKeyAB, a);

        return publicKeyAB;
    }

    /**
     * Subtract one public key from another. A public key is a group element and this function is also used to subtract group element
     * @param publicKeyA A public key
     * @param publicKeyB The public key that is subtracted from the other
     * @return The result as a public key
     */
    public static byte[] subtractPublicKeys(byte[] publicKeyA, byte[] publicKeyB) {
        if (publicKeyB.length != publicKeyLength) throw new IllegalArgumentException("One public key has the wrong length");

        byte[] temp = new byte[publicKeyLength];
        System.arraycopy(publicKeyB, 0, temp, 0, publicKeyLength);
        temp[31] = (byte) (temp[31] ^ 0x80);
        return addPublicKeys(publicKeyA, temp);
    }

    /**
     * Creates an empty unpacked group element. Just for convenience
     * @return Empty unpacked group element
     */
    private static long[][] createUnpackedGroupEl() {
        long[][] unpackedGroupEl = new long[4][];
        unpackedGroupEl[0] = new long[16];
        unpackedGroupEl[1] = new long[16];
        unpackedGroupEl[2] = new long[16];
        unpackedGroupEl[3] = new long[16];
        return unpackedGroupEl;
    }

    /**
     * Unpack group element. Uses unpackneg() from TweetNaclFast and changes the sign
     * @param packedGroupEl The group element that is to be unpacked
     * @return The resulting unpacked group element
     */
    private static long[][] unpack(byte[] packedGroupEl) {
        long[][] unpackedGroupEl = createUnpackedGroupEl();

        int result = TweetNaclFast.unpackneg(unpackedGroupEl, packedGroupEl);
        if (result != 0) throw new IllegalArgumentException("Group element can not be unpacked");

        // Change sign from neg to pos
        TweetNaclFast.Z(unpackedGroupEl[0], TweetNaclFast.gf0, unpackedGroupEl[0]);
        TweetNaclFast.M(unpackedGroupEl[3], unpackedGroupEl[0], unpackedGroupEl[1]);

        return unpackedGroupEl;
    }

    /**
     * Create a EdDSA signature.
     * @param message   The message to be signed.
     * @param publicKey The public key of the signer
     * @param secretKey The secret key of the signer
     * @return          The signature
     */
    public static byte[] signCreate(byte[] message, byte[] publicKey, byte[] secretKey) {
        if (message == null) throw new IllegalArgumentException("Message is null");
        if (publicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (secretKey.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] sign = new byte[m2Length + message.length];

        byte[] pseudoRandom = calculateRand(message, secretKey);
        byte[] randomGroupEl = calculatePublicKey(pseudoRandom);

        byte[] hash = calculateHash(randomGroupEl, publicKey, message);
        byte[] signature = calculateSignature(pseudoRandom, hash, secretKey);

        System.arraycopy(randomGroupEl, 0, sign, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(signature, 0, sign, TweetNaclFast.ScalarMult.groupElementLength, TweetNaclFast.ScalarMult.scalarLength);
        System.arraycopy(message, 0, sign, signatureLength, message.length);

        return sign;
    }

    /**
     * Verify a EdDSA signature.
     * @param signature The signature to be verified
     * @param publicKey The public key to verify the signature against
     * @return          True if the signature is valid
     */
    public static boolean signVerify(byte[] signature, byte[] publicKey) {
        if (signature == null) throw new IllegalArgumentException("Signature is null");
        if (signature.length < signatureLength) throw new IllegalArgumentException("Signature is to short");
        if (publicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");

        byte[] tmp = new byte[signature.length];
        return TweetNaclFast.crypto_sign_open(tmp, 0, signature, 0, signature.length, publicKey) == 0;
    }

    /**
     * The first of 3 functions that together creates one valid EdDSA signature from two separate key pairs.
     * Done is such a way that that two devices with separate key pairs can sign without there key pairs ever
     * existing in the same device. Before this functions is executed the key pairs public keys has to be
     * added with addPublicKeys() to get the virtualPublicKey.
     * m1 and m2 is recommended to be sent in a encrypted channel with forward secrecy such as saltChannel
     * *****************************************
     *   Device 1                Device 2
     * signCreateDual1()            |
     *      |-----------m1--------> |
     *      |                  signCreateDual2()
     *      | <---------m2----------|
     * signCreateDual3()            |
     * *****************************************
     * @param message          The message to be signed
     * @param virtualPublicKey The addition of the two key pairs public keys that shall sign the message.
     * @param secretKeyA       The first secret key of the ones that shall sign
     * @return                 m1 message to be used in signCreateDual2() and signCreateDual3()
     */
    public static byte[] signCreateDual1(byte[] message, byte[] virtualPublicKey, byte[] secretKeyA) {
        if (message == null) throw new IllegalArgumentException("Message is null");
        if (virtualPublicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (secretKeyA.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] m1 = new byte[m1HeaderLength + message.length];

        byte[] pseudoRandomA = calculateRand(message, secretKeyA);
        byte[] randomGroupElA = calculatePublicKey(pseudoRandomA);

        System.arraycopy(virtualPublicKey, 0, m1, 0, publicKeyLength);
        System.arraycopy(randomGroupElA, 0, m1, publicKeyLength, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(message, 0, m1, m1HeaderLength, message.length);
        return m1;
    }

    /**
     * See description in signCreateDual1()
     * @param m1         The m1 message from signCreateDual1
     * @param secretKeyB The second secret key of the ones that shall sign
     * @return           m2 message to be used in signCreateDual3()
     */
    public static byte[] signCreateDual2(byte[] m1, byte[] secretKeyB) {
        if (m1.length <= m1HeaderLength) throw new IllegalArgumentException("M1 message is to short");
        if (secretKeyB.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] m2 = new byte[m2Length];
        byte[] virtualPublicKey = Arrays.copyOfRange(m1, 0, publicKeyLength);
        byte[] randomGroupElA = Arrays.copyOfRange(m1, publicKeyLength, m1HeaderLength);
        byte[] message = Arrays.copyOfRange(m1, m1HeaderLength, m1.length);

        byte[] pseudoRandomB = calculateRand(message, secretKeyB);
        byte[] randomGroupElB = calculatePublicKey(pseudoRandomB);
        byte[] randomGroupEl = addPublicKeys(randomGroupElA, randomGroupElB);

        byte[] hash = calculateHash(randomGroupEl, virtualPublicKey, message);
        byte[] signatureB = calculateSignature(pseudoRandomB, hash, secretKeyB);

        System.arraycopy(randomGroupElB, 0, m2, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(signatureB, 0, m2, TweetNaclFast.ScalarMult.groupElementLength, TweetNaclFast.ScalarMult.scalarLength);
        return m2;
    }

    /**
     * See description in signCreateDual1()
     * @param m1         The m1 message from signCreateDual1
     * @param m2         The m2 message from signCreateDual2
     * @param publicKeyA The public key of the secret key used
     * @param secretKeyA The first secret key of the ones that shall sign
     * @return           The signature
     */
    public static byte[] signCreateDual3(byte[] m1, byte[] m2, byte[] publicKeyA, byte[] secretKeyA) {
        if (m1.length <= m1HeaderLength) throw new IllegalArgumentException("M1 message is to short");
        if (m2.length != m2Length) throw new IllegalArgumentException("M2 message has the wrong length");
        if (publicKeyA.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (secretKeyA.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] virtualPublicKey = Arrays.copyOfRange(m1, 0, publicKeyLength);
        byte[] message = Arrays.copyOfRange(m1, m1HeaderLength, m1.length);
        byte[] randomGroupElB = Arrays.copyOfRange(m2, 0, TweetNaclFast.ScalarMult.groupElementLength);
        byte[] signatureB = Arrays.copyOfRange(m2, TweetNaclFast.ScalarMult.groupElementLength, m2Length);
        byte[] sign = new byte[signatureLength + message.length];

        // Repeat signCreateDual1
        byte[] pseudoRandomA = calculateRand(message, secretKeyA);
        byte[] randomGroupElA = calculatePublicKey(pseudoRandomA);
        byte[] randomGroupEl = addPublicKeys(randomGroupElA, randomGroupElB);

        byte[] hash = calculateHash(randomGroupEl, virtualPublicKey, message);
        byte[] publicKeyB = subtractPublicKeys(virtualPublicKey, publicKeyA);
        if (!validateSignatureSpecial(publicKeyB, randomGroupElB, signatureB, hash))
            throw new IllegalArgumentException("M2 do not validate correctly");

        byte[] signatureA = calculateSignature(pseudoRandomA, hash, secretKeyA);
        byte[] signature = addScalars(signatureA, signatureB);

        System.arraycopy(randomGroupEl, 0, sign, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(signature, 0, sign, TweetNaclFast.ScalarMult.groupElementLength, TweetNaclFast.ScalarMult.scalarLength);
        System.arraycopy(message, 0, sign, signatureLength, message.length);
        return sign;
    }

    /**
     * Function used to create the pseudo random used used in a EdDSA signature
     * @param message   The signature message used as seed to the random
     * @param secretKey The secret key used as seed to the random
     * @return          The pseudo random
     */
    private static byte[] calculateRand(byte[] message, byte[] secretKey) {
        byte[] rand = new byte[hashLength];
        byte[] tempBuffer = new byte[secretRandomLength + message.length];

        System.arraycopy(secretKey, TweetNaclFast.ScalarMult.scalarLength, tempBuffer, 0, secretRandomLength);
        System.arraycopy(message, 0, tempBuffer, secretRandomLength, message.length);

        TweetNaclFast.crypto_hash(rand, tempBuffer, 0, secretRandomLength + message.length);
        TweetNaclFast.reduce(rand);
        return rand;
    }

    /**
     * Used to calculate the hash used in both verify and create EdDSA signatures
     * @param randomGroupEl The pseudo random point used in the signature
     * @param publicKey     The public key of the signature
     * @param message       The message of the signature
     * @return              The hash value.
     */
    private static byte[] calculateHash(byte[] randomGroupEl, byte[] publicKey, byte[] message) {
        byte[] hash = new byte[hashLength];
        byte[] tempBuffer = new byte[TweetNaclFast.ScalarMult.groupElementLength + publicKeyLength + message.length];

        System.arraycopy(randomGroupEl, 0, tempBuffer, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(publicKey, 0, tempBuffer, TweetNaclFast.ScalarMult.groupElementLength, publicKeyLength);
        System.arraycopy(message, 0, tempBuffer, TweetNaclFast.ScalarMult.groupElementLength + publicKeyLength, message.length);
        TweetNaclFast.crypto_hash(hash, tempBuffer, 0, tempBuffer.length);

        TweetNaclFast.reduce(hash);
        return hash;
    }

    /**
     * The calculation of the scalars in a EdDSA signature
     * @param rand      The pseudo random
     * @param hash      The hash value
     * @param secretKey The secret key
     * @return          The scalar to be included in the signature
     */
    private static byte[] calculateSignature(byte[] rand, byte[] hash, byte[] secretKey) {
        byte[] signature = new byte[TweetNaclFast.ScalarMult.scalarLength];

        int i, j;
        long[] x = new long[64];
        for (i = 0; i < 64; i++) x[i] = 0;
        for (i = 0; i < 32; i++) x[i] = (long) (rand[i] & 0xff);
        for (i = 0; i < 32; i++) for (j = 0; j < 32; j++) x[i + j] += (hash[i] & 0xff) * (long) (secretKey[j] & 0xff);
        TweetNaclFast.modL(signature, 0, x);
        return signature;
    }

    /**
     * In signCreateDual3() the function validates m2. M2 is quite close to a signature with the difference how the hash
     * is calculated. So this function do the exact same as a usual EdDSA verify dose with the exception that the hash
     * comes from a parameter.
     * @param publicKey     The public key the signature sghall be validated agains
     * @param randomGroupEl The first part of the signature
     * @param signature     The second part of the signature
     * @param hash          The hash used in the validation
     * @return              True if valid
     */
    private static boolean validateSignatureSpecial(byte[] publicKey, byte[] randomGroupEl, byte[] signature, byte[] hash) {
        long[][] p = createUnpackedGroupEl();
        long[][] q = createUnpackedGroupEl();
        byte[] t = new byte[TweetNaclFast.ScalarMult.groupElementLength];

        if (TweetNaclFast.unpackneg(q, publicKey) != 0) return false;
        TweetNaclFast.scalarmult(p, q, hash, 0);
        TweetNaclFast.scalarbase(q, signature, 0);
        TweetNaclFast.add(p, q);
        TweetNaclFast.pack(t, p);
        return TweetNaclFast.crypto_verify_32(randomGroupEl, 0, t, 0) == 0;
    }

    /**
     * Encryption a message with forward secrecy if random is forgotten. Uses Ed25519
     * @param message     The message to be encrypted
     * @param nonce       The nonce use
     * @param toPublicKey The public key to encrypt to
     * @param random      Random
     * @return            The cipher message
     */
    public static byte[] encrypt(byte[] message, byte[] nonce, byte[] toPublicKey, byte[] random) {
        if (message == null) throw new IllegalArgumentException("The message is null");
        if (nonce.length != nonceLength) throw new IllegalArgumentException("Nonce has the wrong length");
        if (toPublicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (random.length != seedLength) throw new IllegalArgumentException("Random seed has the wrong length");

        byte[] tempPublicKey = new byte[publicKeyLength];
        byte[] tempSecretKey = new byte[secretKeyLength];
        byte[] sharedGroupEl = new byte[TweetNaclFast.ScalarMult.groupElementLength];
        createKeyPair(tempPublicKey, tempSecretKey, random);

        long[][] p = createUnpackedGroupEl();
        long[][] q = unpack(toPublicKey);
        TweetNaclFast.scalarmult(p, q, tempSecretKey, 0);
        TweetNaclFast.pack(sharedGroupEl, p);

        byte[] cipherText = encryptWithSharedGroupEl(message, nonce, sharedGroupEl);

        byte[] cipherMessage = new byte[cipherMessageHeaderLength + cipherText.length];
        System.arraycopy(nonce, 0, cipherMessage, 0, nonceLength);
        System.arraycopy(tempPublicKey, 0, cipherMessage, nonceLength, publicKeyLength);
        System.arraycopy(cipherText, 0, cipherMessage, cipherMessageHeaderLength, cipherText.length);
        return cipherMessage;
    }

    /**
     * Decryption function
     * @param cipherMessage The cipher message
     * @param nonce         (out) The nonce that was use in hte encryption
     * @param secretKey     The secret key encrypted to
     * @return              The decrypted message
     */
    public static byte[] decrypt(byte[] cipherMessage, byte[] nonce, byte[] secretKey) {
        if (cipherMessage.length <= cipherMessageHeaderLength)
            throw new IllegalArgumentException("The cipher message is to short");
        if (nonce.length != nonceLength) throw new IllegalArgumentException("Nonce has the wrong length");
        if (secretKey.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] cipherText = Arrays.copyOfRange(cipherMessage, cipherMessageHeaderLength, cipherMessage.length);
        System.arraycopy(cipherMessage, 0, nonce, 0, nonceLength);

        byte[] sharedGroupEl = decryptDual1(cipherMessage, secretKey);
        return decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl);
    }

    /**
     * The first of 2 functions that together can decrypt a cipher message from encrypt() encrypted to
     * an virtual key pair.
     * d1 is recommended to be sent in a encrypted channel with forward secrecy such as saltChannel
     * *****************************************
     *   Device 1                Device 2
     * decryptDual1()               |
     *      |-----------d1--------> |
     *      |                  decryptDual2()
     * *****************************************
     * @param cipherMessage The cipher message to be decrypted
     * @param secretKeyA    The first secret key to be used in hte decryption
     * @return              d1 a message used in decryptDual2() to finish the decryption
     */
    public static byte[] decryptDual1(byte[] cipherMessage, byte[] secretKeyA) {
        if (cipherMessage.length <= cipherMessageHeaderLength)
            throw new IllegalArgumentException("The cipher message is to short");
        if (secretKeyA.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        byte[] d1 = new byte[d1Length];
        byte[] tempPublicKey = Arrays.copyOfRange(cipherMessage, nonceLength, cipherMessageHeaderLength);

        long[][] p = createUnpackedGroupEl();
        long[][] q = unpack(tempPublicKey);
        TweetNaclFast.scalarmult(p, q, secretKeyA, 0);
        TweetNaclFast.pack(d1, p);
        return d1;
    }

    /**
     * See description in decryptDual1()
     * @param d1            d1 a message from decryptDual1()
     * @param cipherMessage The cipher message to be decrypted
     * @param nonce         (out) The nonce that was use in hte encryption
     * @param secretKeyB    The second secret key to be used in hte decryption
     * @return              The decrypted message
     */
    public static byte[] decryptDual2(byte[] d1, byte[] cipherMessage, byte[] nonce, byte[] secretKeyB) {
        if (d1.length != d1Length) throw new IllegalArgumentException("D1 has the wrong length");
        if (cipherMessage.length <= cipherMessageHeaderLength)
            throw new IllegalArgumentException("The cipher message is to short");
        if (nonce.length != nonceLength) throw new IllegalArgumentException("Nonce has the wrong length");
        if (secretKeyB.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");

        System.arraycopy(cipherMessage, 0, nonce, 0, nonceLength);
        byte[] tempPublicKey = Arrays.copyOfRange(cipherMessage, nonceLength, cipherMessageHeaderLength);
        byte[] cipherText = Arrays.copyOfRange(cipherMessage, cipherMessageHeaderLength, cipherMessage.length);
        byte[] sharedGroupEl = new byte[TweetNaclFast.ScalarMult.groupElementLength];

        long[][] p = createUnpackedGroupEl();
        long[][] q = unpack(tempPublicKey);
        TweetNaclFast.scalarmult(p, q, secretKeyB, 0);

        q = unpack(d1);
        TweetNaclFast.add(p, q);
        TweetNaclFast.pack(sharedGroupEl, p);

        return decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl);
    }

    /**
     * Encrypt a message with a shared group element. A wrapper around the TweetNaCl functions to not have to handel
     * all buffers in the higher layers
     * @param message       Message to be encrypted
     * @param nonce         The nonce
     * @param sharedGroupEl The shared group element used as key
     * @return              The cipher text
     */
    private static byte[] encryptWithSharedGroupEl(byte[] message, byte[] nonce, byte[] sharedGroupEl) {
        byte[] sharedKey = new byte[TweetNaclFast.Box.sharedKeyLength];
        TweetNaclFast.crypto_core_hsalsa20(sharedKey, TweetNaclFast._0, sharedGroupEl, TweetNaclFast.sigma);

        byte[] messageBuffer = new byte[TweetNaclFast.Box.zerobytesLength + message.length];
        byte[] cipherBuffer = new byte[messageBuffer.length];
        System.arraycopy(message, 0, messageBuffer, TweetNaclFast.Box.zerobytesLength, message.length);

        TweetNaclFast.crypto_box_afternm(cipherBuffer, messageBuffer, messageBuffer.length, nonce, sharedKey);

        return Arrays.copyOfRange(cipherBuffer, TweetNaclFast.Box.boxzerobytesLength, cipherBuffer.length);
    }

    /**
     * Decrypt a cipher text with a shared group element. A wrapper around the TweetNaCl functions to not have to handel
     * all buffers in the higher layers
     * @param cipherText    Data to be decrypted
     * @param nonce         The nonce
     * @param sharedGroupEl The shared group element used as key
     * @return              The decrypted message
     */
    private static byte[] decryptWithSharedGroupEl(byte[] cipherText, byte[] nonce, byte[] sharedGroupEl) {
        byte[] sharedKey = new byte[TweetNaclFast.Box.sharedKeyLength];
        TweetNaclFast.crypto_core_hsalsa20(sharedKey, TweetNaclFast._0, sharedGroupEl, TweetNaclFast.sigma);

        byte[] cipherBuffer = new byte[TweetNaclFast.Box.boxzerobytesLength + cipherText.length];
        byte[] messageBuffer = new byte[cipherBuffer.length];
        System.arraycopy(cipherText, 0, cipherBuffer, TweetNaclFast.Box.boxzerobytesLength, cipherText.length);

        if (TweetNaclFast.crypto_box_open_afternm(messageBuffer, cipherBuffer, cipherBuffer.length, nonce, sharedKey) != 0) {
            throw new IllegalArgumentException("Can not decrypt message");
        }

        return Arrays.copyOfRange(messageBuffer, TweetNaclFast.Box.zerobytesLength, messageBuffer.length);
    }
}