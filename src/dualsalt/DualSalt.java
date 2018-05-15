package dualsalt;

public class DualSalt {

    // TODO
    // Build with JAVA 7
    // check in params in public functions
    // Function description
    // Class description (design decisions)
    // Readme hello world
    // Disclaimer
    // Thanks
    // Negative testcase
    // Test with test vector from EdDSA (Ed25519) python

    private static final int secretRandomLength = 32;

    public static final int secretKeyLength = TweetNaclFast.ScalarMult.scalarLength + secretRandomLength;

    public static final int publicKeyLength = TweetNaclFast.ScalarMult.groupElementLength;

    public static final int signatureLength = TweetNaclFast.Signature.signatureLength;

    public static final int nonceLength = TweetNaclFast.Box.nonceLength;

    public static final int seedLength = TweetNaclFast.Signature.seedLength;

    private static final int cipherMessageHeaderLength = nonceLength + publicKeyLength;

    private static final int m1HeaderLength = TweetNaclFast.ScalarMult.groupElementLength + publicKeyLength;

    private static final int m2Length = signatureLength;

    private static final int d1HeaderLength = TweetNaclFast.ScalarMult.groupElementLength;

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
     * @return          Returns the public key
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
     * This function is used to "rotate" the two secret keys used to build up a dual key (virtual key pair). The to
     * key pairs kan be changed in such a way that the addition of there two public keys still adds up to the same value.
     * Run rotateKey() on the first key pair with the parameter first sat to true and then run rotateKey() on the second
     * key pair with the param first set to false. Reuse the same data for random1 both time.
     *
     * createKeyPair(A, a, r1)
     * createKeyPair(B, b, r2)
     * C1 = addPublicKeys(A, B)
     * rotateKey(A, a, r2, true, r4) <- Change A and a
     * rotateKey(B, b, r2, false, r5) <- Change B and b
     * C1 == addPublicKeys(A, B)
     *
     * @param publicKey (out) The new public key after rotation
     * @param secretKey (in/out) The earlier secret key in and the resulting secret key out after rotation
     * @param random1   Random for the scalar multiplication part. Reuse for both parts in a virtual key pair
     * @param first     Shall be different between the to parts of the virtual key pair
     * @param random2   Random used for signing shall be different every time
     */
    public static void rotateKey(byte[] publicKey, byte[] secretKey, byte[] random1, boolean first, byte[] random2) {
        if (publicKey.length != publicKeyLength) throw new IllegalArgumentException("Public key has the wrong length");
        if (secretKey.length != secretKeyLength) throw new IllegalArgumentException("Secret key has the wrong length");
        if (random1.length != seedLength) throw new IllegalArgumentException("Random1 source has the wrong length");
        if (random2.length != seedLength) throw new IllegalArgumentException("Random2 source has the wrong length");

        byte[] newScalar;
        if (first) {
            newScalar = addScalars(secretKey, random1);
        } else {
            newScalar = subtractScalars(secretKey, random1);
        }
        System.arraycopy(newScalar, 0, secretKey, 0, TweetNaclFast.ScalarMult.scalarLength);
        System.arraycopy(random2, 0, secretKey, TweetNaclFast.ScalarMult.scalarLength, secretRandomLength);
        byte[] tempPublicKey = calculatePublicKey(secretKey);
        System.arraycopy(tempPublicKey, 0, publicKey, 0, publicKeyLength);
    }

    /**
     * Add two scalar to each others
     * @param scalarA The first scalar
     * @param scalarB The second scalar
     * @return        The result as a scalar
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
     * @return        The result as a scalar
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
     * @return           The result as a public key
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
     * @return           The result as a public key
     */
    public static byte[] subtractPublicKeys(byte[] publicKeyA, byte[] publicKeyB) {
        byte[] temp = new byte[publicKeyLength];
        System.arraycopy(publicKeyB, 0, temp, 0, publicKeyLength);
        temp[31] = (byte) (temp[31] ^ 0x80);
        return addPublicKeys(publicKeyA, temp);
    }

    /**
     * Creates an empty unpacked group element. Just for convenience
     * @return Empty unpacked group element
     */
    private static long[][] createUnpackedGroupEl(){
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
     * @return                   The resulting unpacked group element
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


    public static void signCreate(byte[] signature, byte[] message, byte[] publicKey, byte[] secretKey) {
        // Changed as little as possible from TweetSalts crypto_sign(). One of the changes is the deletion of
        // the hashing of the secret key.
        byte[]  h = new byte[64], r = new byte[64];
        int n = message.length;
        int i, j;
        long [] x = new long[64];

        long [] [] p = new long [4] [];
        p[0] = new long [16];
        p[1] = new long [16];
        p[2] = new long [16];
        p[3] = new long [16];

        for (i = 0; i < n; i ++) signature[64 + i] = message[i];

        for (i = 0; i < 32; i ++) signature[32 + i] = secretKey[32 + i];

        TweetNaclFast.crypto_hash(r, signature,32, n+32);
        TweetNaclFast.reduce(r);
        TweetNaclFast.scalarbase(p, r,0);
        TweetNaclFast.pack(signature,p);

        for (i = 0; i < 32; i ++) signature[i+32] = publicKey[i];
        TweetNaclFast.crypto_hash(h, signature,0, n + 64);
        TweetNaclFast.reduce(h);

        for (i = 0; i < 64; i ++) x[i] = 0;
        for (i = 0; i < 32; i ++) x[i] = (long) (r[i]&0xff);
        for (i = 0; i < 32; i ++) for (j = 0; j < 32; j ++) x[i+j] += (h[i]&0xff) * (long) (secretKey[j]&0xff);

        TweetNaclFast.modL(signature,32, x);
    }

    public static boolean  signVerify(byte [] signature, byte [] publicKey){
        byte [] tmp = new byte[signature.length];
        return TweetNaclFast.crypto_sign_open(tmp, 0, signature, 0, signature.length, publicKey)==0;
    }

    public static byte[] signCreateDual1(byte[] message, byte[]  virtualPublicKey, byte[] secretKeyA){
        byte[] m1 = new byte[m1HeaderLength+message.length];
        System.arraycopy(virtualPublicKey, 0, m1, 0, publicKeyLength);

        byte[] pseudoRandomA = calculateRand(message, secretKeyA);
        byte[] randomGroupElA = calculatePublicKey(pseudoRandomA);
        System.arraycopy(randomGroupElA, 0, m1, 32, publicKeyLength);

        System.arraycopy(message, 0, m1, 64, message.length);
        return m1;
    }

    public static byte[] signCreateDual2( byte[] m1, byte[] secretKeyB){
        byte[] m2 = new byte[m2Length];
        byte[] virtualPublicKey = new byte[publicKeyLength];
        byte[] randomGroupElA = new byte[TweetNaclFast.ScalarMult.groupElementLength];
        byte[] message = new byte[m1.length - m1HeaderLength];

        System.arraycopy(m1, 0, virtualPublicKey, 0, publicKeyLength);
        System.arraycopy(m1, 32, randomGroupElA, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(m1, 64, message, 0, message.length);

        byte[] pseudoRandomB = calculateRand(message, secretKeyB);
        byte[] randomGroupElB = calculatePublicKey(pseudoRandomB);
        byte[] randomGroupEl = addPublicKeys(randomGroupElA, randomGroupElB);
        System.arraycopy(randomGroupElB, 0, m2, 0, TweetNaclFast.ScalarMult.groupElementLength);

        byte[] hash = calculateHash(randomGroupEl, virtualPublicKey, message);
        byte[] signatureB = calculateSignature( pseudoRandomB, hash, secretKeyB);

        System.arraycopy(signatureB, 0, m2, 32, TweetNaclFast.ScalarMult.scalarLength);
        return m2;
    }

    public static byte[] signCreateDual3( byte[] m1, byte[] m2, byte[] publicKeyA, byte[] secretKeyA){
        byte[] virtualPublicKey = new byte[publicKeyLength];
        byte[] message = new byte[m1.length - m1HeaderLength];
        byte[] randomGroupElB = new byte[TweetNaclFast.ScalarMult.groupElementLength];
        byte[] signatureB = new byte[TweetNaclFast.ScalarMult.scalarLength];

        System.arraycopy(m1, 0, virtualPublicKey, 0, publicKeyLength);
        System.arraycopy(m1, m1HeaderLength, message, 0, message.length);
        System.arraycopy(m2, 0, randomGroupElB, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(m2, TweetNaclFast.ScalarMult.groupElementLength, signatureB, 0, TweetNaclFast.ScalarMult.scalarLength);

        // Repeat signCreateDual1
        byte[] pseudoRandomA = calculateRand(message, secretKeyA);
        byte[] randomGroupElA = calculatePublicKey(pseudoRandomA);
        byte[] randomGroupEl = addPublicKeys(randomGroupElA, randomGroupElB);

        byte[] hash = calculateHash(randomGroupEl, virtualPublicKey, message);
        byte[] publicKeyB = subtractPublicKeys(virtualPublicKey, publicKeyA);
        if (validateSignatureSpecial(publicKeyB, randomGroupElB, signatureB, hash)) throw new IllegalArgumentException("M2 do not validate correctly");

        byte[] signatureA = calculateSignature( pseudoRandomA, hash, secretKeyA);
        byte[] signature = addScalars(signatureA, signatureB);

        byte[] sign = new byte[signatureLength + message.length];
        System.arraycopy(randomGroupEl, 0, sign, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(signature, 0, sign, TweetNaclFast.ScalarMult.groupElementLength, TweetNaclFast.ScalarMult.scalarLength);
        System.arraycopy(message, 0, sign, signatureLength, message.length);
        return sign;
    }

    private static byte[] calculateRand(byte [] message, byte [] secretKey){

        byte[] rand = new byte[64]; // 64 instead of 32. Reduction in the end
        byte[] tempBuffer = new byte[secretRandomLength + message.length];

        System.arraycopy(secretKey, TweetNaclFast.ScalarMult.scalarLength, tempBuffer, 0, secretRandomLength);
        System.arraycopy(message, 0, tempBuffer, secretRandomLength, message.length);

        TweetNaclFast.crypto_hash(rand, tempBuffer,0, secretRandomLength + message.length);
        TweetNaclFast.reduce(rand);
        return rand;
    }

    private static byte[] calculateHash(byte [] randomGroupEl, byte [] publicKey, byte [] message){
        byte[] hash = new byte[64]; // 64 instead of 32. Reduction in the end
        byte[] tempBuffer = new byte[TweetNaclFast.ScalarMult.groupElementLength + publicKeyLength + message.length];

        System.arraycopy(randomGroupEl, 0, tempBuffer, 0, TweetNaclFast.ScalarMult.groupElementLength);
        System.arraycopy(publicKey, 0, tempBuffer, 32, publicKeyLength);
        System.arraycopy(message, 0, tempBuffer, TweetNaclFast.ScalarMult.groupElementLength + publicKeyLength, message.length);
        TweetNaclFast.crypto_hash(hash, tempBuffer,0, tempBuffer.length);

        TweetNaclFast.reduce(hash);
        return hash;
    }

    private static byte[] calculateSignature(byte [] rand, byte [] hash, byte [] secretKey){
        byte[] signature = new byte[TweetNaclFast.ScalarMult.scalarLength];

        int i, j;
        long [] x = new long[64];
        for (i = 0; i < 64; i ++) x[i] = 0;
        for (i = 0; i < 32; i ++) x[i] = (long) (rand[i]&0xff);
        for (i = 0; i < 32; i ++) for (j = 0; j < 32; j ++) x[i+j] += (hash[i]&0xff) * (long) (secretKey[j]&0xff);
        TweetNaclFast.modL(signature,0, x);
        return signature;
    }

    private static boolean validateSignatureSpecial(byte[] publicKey, byte[] randomGroupEl, byte[] signature, byte[] hash) {
        long [] [] p = createUnpackedGroupEl();
        long [] [] q = createUnpackedGroupEl();
        byte[] t = new byte[TweetNaclFast.ScalarMult.groupElementLength];

        if (TweetNaclFast.unpackneg(q, publicKey)!=0) return false;
        TweetNaclFast.scalarmult(p,q, hash,0);
        TweetNaclFast.scalarbase(q, signature,0);
        TweetNaclFast.add(p,q);
        TweetNaclFast.pack(t,p);
        return TweetNaclFast.crypto_verify_32(randomGroupEl, 0, t, 0) != 0;
    }

    public static byte[] encrypt(byte[] message, byte[] nonce, byte[] toPublicKey, byte[] random){
        byte[] tempPublicKey = new byte[publicKeyLength];
        byte[] tempSecretKey = new byte[secretKeyLength];
        byte[] sharedGroupEl = new byte[TweetNaclFast.ScalarMult.groupElementLength];
        createKeyPair(tempPublicKey, tempSecretKey, random);

        long[][] p = createUnpackedGroupEl();
        long[][] q = unpack(toPublicKey);
        TweetNaclFast.scalarmult(p, q, tempSecretKey, 0);
        TweetNaclFast.pack(sharedGroupEl, p);

        byte [] cipherText =  encryptWithSharedGroupEl(message, nonce, sharedGroupEl);

        byte [] cipherMessage = new byte[cipherMessageHeaderLength + cipherText.length];
        System.arraycopy(nonce, 0, cipherMessage, 0, nonceLength);
        System.arraycopy(tempPublicKey, 0, cipherMessage, nonceLength, publicKeyLength);
        System.arraycopy(cipherText, 0, cipherMessage, cipherMessageHeaderLength, cipherText.length);
        return cipherMessage;
    }

    public static byte[] decrypt(byte[] cipherMessage, byte[] nonce, byte[] secretKey){
        byte[] cipherText = new byte[cipherMessage.length- cipherMessageHeaderLength];
        System.arraycopy(cipherMessage, cipherMessageHeaderLength, cipherText, 0, cipherText.length);
        System.arraycopy(cipherMessage, 0, nonce, 0, nonceLength);

        byte[] sharedGroupEl = decryptDual1(cipherMessage, secretKey);
        return decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl);
    }

    public static byte[] decryptDual1(byte[] cipherMessage, byte[] secretKey){
        byte[] groupEl = new byte[d1HeaderLength];
        byte[] tempPublicKey = new byte[publicKeyLength];
        System.arraycopy(cipherMessage, nonceLength, tempPublicKey, 0, publicKeyLength);

        long[][] p = createUnpackedGroupEl();
        long[][] q = unpack(tempPublicKey);
        TweetNaclFast.scalarmult(p, q, secretKey, 0);
        TweetNaclFast.pack(groupEl, p);
        return groupEl;
    }

    public static byte[] decryptDual2(byte[] d1, byte[] cipherMessage, byte[] nonce, byte[] secretKey){
        byte[] tempPublicKey = new byte[publicKeyLength];
        byte[] sharedGroupEl = new byte[TweetNaclFast.ScalarMult.groupElementLength];
        byte[] cipherText = new byte[cipherMessage.length- cipherMessageHeaderLength];
        System.arraycopy(cipherMessage, 0, nonce, 0, nonceLength);
        System.arraycopy(cipherMessage, nonceLength, tempPublicKey, 0, publicKeyLength);
        System.arraycopy(cipherMessage, cipherMessageHeaderLength, cipherText, 0, cipherText.length);

        long[][] p = createUnpackedGroupEl();
        long[][] q = unpack( tempPublicKey);
        TweetNaclFast.scalarmult(p, q, secretKey, 0);

        q = unpack(d1);
        TweetNaclFast.add(p, q);
        TweetNaclFast.pack(sharedGroupEl, p);

        return decryptWithSharedGroupEl(cipherText, nonce, sharedGroupEl);
    }

    private static byte[] encryptWithSharedGroupEl( byte[] message, byte[] nonce, byte[] sharedGroupEl) {
        byte[] sharedKey = new byte[TweetNaclFast.Box.sharedKeyLength];
        TweetNaclFast.crypto_core_hsalsa20(sharedKey, TweetNaclFast._0, sharedGroupEl, TweetNaclFast.sigma);

        byte [] messageBuffer = new byte[TweetNaclFast.Box.zerobytesLength+message.length];
        byte [] cipherBuffer = new byte[messageBuffer.length];
        System.arraycopy(message, 0, messageBuffer, TweetNaclFast.Box.zerobytesLength, message.length);

        TweetNaclFast.crypto_box_afternm(cipherBuffer, messageBuffer, messageBuffer.length, nonce, sharedKey);

        byte [] cipherText = new byte[messageBuffer.length - TweetNaclFast.Box.boxzerobytesLength];
        System.arraycopy(cipherBuffer, TweetNaclFast.Box.boxzerobytesLength, cipherText, 0, messageBuffer.length - TweetNaclFast.Box.boxzerobytesLength);
        return cipherText;
    }

    private static byte[] decryptWithSharedGroupEl( byte[] cipherText, byte[] nonce, byte[] sharedGroupEl) {
        byte[] sharedKey = new byte[TweetNaclFast.Box.sharedKeyLength];
        TweetNaclFast.crypto_core_hsalsa20(sharedKey, TweetNaclFast._0, sharedGroupEl, TweetNaclFast.sigma);

        byte [] cipherBuffer = new byte[TweetNaclFast.Box.boxzerobytesLength+cipherText.length];
        byte [] messageBuffer = new byte[cipherBuffer.length];
        System.arraycopy(cipherText, 0, cipherBuffer, TweetNaclFast.Box.boxzerobytesLength, cipherText.length);

        if (TweetNaclFast.crypto_box_open_afternm(messageBuffer, cipherBuffer, cipherBuffer.length, nonce, sharedKey) != 0) {
            throw new IllegalArgumentException("Can not decrypt message");
        }

        byte [] message = new byte[messageBuffer.length-TweetNaclFast.Box.zerobytesLength];
        System.arraycopy(messageBuffer, TweetNaclFast.Box.zerobytesLength, message, 0, message.length);
        return message;
    }
}
