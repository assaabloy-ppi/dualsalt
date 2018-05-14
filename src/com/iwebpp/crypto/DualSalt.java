package com.iwebpp.crypto;

import com.iwebpp.crypto.TweetNaclFast.Box;
import com.iwebpp.crypto.TweetNaclFast.ScalarMult;

public class DualSalt {

    // TODO
    // Change domain
    // Build with JAVA 7
    // Change for to System.arrayCopy
    // Negative testcase
    // Function description
    // Class description (design decisions)
    // Readme hello world
    // Disclaimer
    // Thanks
    // Exceptions instead of null
    // check in params in public functions
    // Test with test vector from EdDSA (Ed25519) python

    private static final int secretRandomLength = 32;

    public static final int secretKeyLength = ScalarMult.scalarLength + secretRandomLength;

    public static final int publicKeyLength = ScalarMult.groupElementLength;

    public static final int signatureLength = TweetNaclFast.Signature.signatureLength;

    public static final int nonceLength = Box.nonceLength;

    public static final int seedLength = TweetNaclFast.Signature.seedLength;

    private static final int cipherMessageHeaderLength = nonceLength + publicKeyLength;

    private static final int m1HeaderLength = ScalarMult.groupElementLength + publicKeyLength;

    private static final int m2Length = signatureLength;

    private static final int d1HeaderLength = ScalarMult.groupElementLength;

    public static void createKey(byte[] publicKey, byte[] secretKey, byte[] random) {
        int i;
        TweetNaclFast.crypto_hash(secretKey, random, 0, seedLength);
        secretKey[0] &= 248;
        secretKey[31] &= 127;
        secretKey[31] |= 64;
        byte[] tempPublicKey = calculatePubKey(secretKey);

        for (i = 0; i < publicKeyLength; i++) publicKey[i] = tempPublicKey[i];
    }

    public static byte[] calculatePubKey(byte[] secretKey) {
        byte[] publicKey = new byte[publicKeyLength];
        long[][] p = new long[4][];
        p[0] = new long[16];
        p[1] = new long[16];
        p[2] = new long[16];
        p[3] = new long[16];
        TweetNaclFast.scalarbase(p, secretKey, 0);
        TweetNaclFast.pack(publicKey, p);
        return publicKey;
    }

    public static void rotateKey(byte[] publicKey, byte[] secretKey, byte[] random1, boolean first, byte[] random2) {
        byte[] newScalar;
        int i;
        if (first) {
            newScalar = addScalars(secretKey, random1);
        } else {
            newScalar = subtractScalars(secretKey, random1);
        }
        for (i = 0; i < ScalarMult.scalarLength; i++) secretKey[i] = newScalar[i];
        for (i = 0; i < secretRandomLength; i++) secretKey[ScalarMult.scalarLength + i] = random2[i];
        byte[] tempPublicKey = calculatePubKey(secretKey);
        for (i = 0; i < publicKeyLength; i++) publicKey[i] = tempPublicKey[i];
    }

    public static byte[] addScalars(byte[] scalarA, byte[] scalarB) {
        int i;
        byte[] scalar = new byte[ScalarMult.scalarLength];
        long[] temp = new long[64];
        for (i = 0; i < 64; i++) temp[i] = 0;
        for (i = 0; i < 32; i++) temp[i] = (long) (scalarA[i] & 0xff);
        for (i = 0; i < 32; i++) temp[i] += (long) (scalarB[i] & 0xff);

        TweetNaclFast.modL(scalar, 0, temp);

        return scalar;
    }

    private static byte[] subtractScalars(byte[] scalarA, byte[] scalarB) {
        int i;
        byte[] scalar = new byte[ScalarMult.scalarLength];
        long[] temp = new long[64];
        for (i = 0; i < 64; i++) temp[i] = 0;
        for (i = 0; i < 32; i++) temp[i] = (long) (scalarA[i] & 0xff);
        for (i = 0; i < 32; i++) temp[i] -= (long) (scalarB[i] & 0xff);

        TweetNaclFast.modL(scalar, 0, temp);

        return scalar;
    }

    public static byte[] addPubKeys(byte[] pointA, byte[] pointB) {
        long[][] a = new long[4][];
        a[0] = new long[16];
        a[1] = new long[16];
        a[2] = new long[16];
        a[3] = new long[16];

        long[][] b = new long[4][];
        b[0] = new long[16];
        b[1] = new long[16];
        b[2] = new long[16];
        b[3] = new long[16];
        if (unpack(a, pointA) != 0) return null;
        if (unpack(b, pointB) != 0) return null;

        TweetNaclFast.add(a, b);

        byte[] pointR = new byte[publicKeyLength];
        TweetNaclFast.pack(pointR, a);

        return pointR;
    }

    public static byte[] subtractPubKeys(byte[] pointA, byte[] pointB) {
        int i;
        byte[] temp = new byte[publicKeyLength];
        for (i = 0; i < publicKeyLength; i++) temp[i] = pointB[i];
        temp[31] = (byte) (temp[31] ^ 0x80);
        return addPubKeys(pointA, temp);
    }

    private static int unpack(long[] r[], byte p[])
    {
        int result = TweetNaclFast.unpackneg(r, p);
        if (result != 0){
            return result;
        }

        // Change sign from neg to pos
        TweetNaclFast.Z(r[0], TweetNaclFast.gf0, r[0]);
        TweetNaclFast.M(r[3], r[0], r[1]);

        return 0;
    }

    // Signing

    public static void signCreate(byte [] signature, byte [] message, byte [] publicKey, byte [] secretKey)    {
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

    /*
    M1 = sing1(m, C, a){
        ra = H(a(a(32:64))||m)
        Ra = ra*P
        return (Ra, C, m)
    }

    M2 = sign2(M1, b){
        (Ra, C, M) = M1
        rb = H(b(32:64)||m)
        Rb = rb*P
        R = Ra + Rb
        h = H(R||C||m)
        sb = rb + h*b(0:31)
        return (Rb, sb)
    }

    (R, s) = sign3(M1, M2, a, A){
        (Ra, C, M) = M1
        (Rb, sb) = M2
        R = Ra + Rb
        h = H(R||C||m)
        B = C - A
        s*P == R+h*B
        ra = H(a(32:64)||m)
        sa = ra + h*a(0:31)
        s = sa + sb
        return (R, s)
    }*/

    public static byte[] signCreateDual1(byte[] message, byte[]  virtualPublicKey, byte[] secretKeyA){
        byte[] m1 = new byte[m1HeaderLength+message.length];
        int i;
        for (i = 0; i < publicKeyLength; i ++) m1[i] = virtualPublicKey[i];

        byte[] pseudoRandomA = calculateRand(message, secretKeyA);
        byte[] randomPointA = calculatePubKey(pseudoRandomA);
        for (i = 0; i < publicKeyLength; i ++) m1[ScalarMult.groupElementLength+i] = randomPointA[i];

        for (i = 0; i < message.length; i ++) m1[m1HeaderLength+i] = message[i];
        return m1;
    }

    public static byte[] signCreateDual2( byte[] m1, byte[] secretKeyB){
        byte[] m2 = new byte[m2Length];
        byte[] virtualPublicKey = new byte[publicKeyLength];
        byte[] randomPointA = new byte[ScalarMult.groupElementLength];
        byte[] message = new byte[m1.length - m1HeaderLength];
        int i;

        for (i = 0; i < publicKeyLength; i ++) virtualPublicKey[i] = m1[i];
        for (i = 0; i < ScalarMult.groupElementLength; i ++) randomPointA[i] = m1[publicKeyLength+i];
        for (i = 0; i < message.length; i ++) message[i] = m1[m1HeaderLength+i];

        byte[] pseudoRandomB = calculateRand(message, secretKeyB);
        byte[] randomPointB = calculatePubKey(pseudoRandomB);
        byte[] randomPoint = addPubKeys(randomPointA, randomPointB);
        if (randomPoint == null){
            return null;
        }
        for (i = 0; i < ScalarMult.groupElementLength; i ++) m2[i] = randomPointB[i];

        byte[] hash = calculateHash(randomPoint, virtualPublicKey, message);
        byte[] signatureB = calculateSignature( pseudoRandomB, hash, secretKeyB);

        for (i = 0; i < ScalarMult.scalarLength; i ++) { m2[ScalarMult.groupElementLength+i] = signatureB[i]; }
        return m2;
    }

    public static byte[] signCreateDual3( byte[] m1, byte[] m2, byte[] publicKeyA, byte[] secretKeyA){
        byte[] virtualPublicKey = new byte[publicKeyLength];
        byte[] message = new byte[m1.length - m1HeaderLength];
        byte[] randomPointB = new byte[ScalarMult.groupElementLength];
        byte[] signatureB = new byte[ScalarMult.scalarLength];
        int i;

        for (i = 0; i < publicKeyLength; i ++) virtualPublicKey[i] = m1[i];
        for (i = 0; i < message.length; i ++) message[i] = m1[m1HeaderLength+i];
        for (i = 0; i < ScalarMult.groupElementLength; i ++) randomPointB[i] = m2[i];
        for (i = 0; i < ScalarMult.scalarLength; i ++) signatureB[i] = m2[ScalarMult.groupElementLength+i];

        // Repeat signCreateDual1
        byte[] pseudoRandomA = calculateRand(message, secretKeyA);
        byte[] randomPointA = calculatePubKey(pseudoRandomA);
        byte[] randomPoint = addPubKeys(randomPointA, randomPointB);
        if (randomPoint == null) return null;

        byte[] hash = calculateHash(randomPoint, virtualPublicKey, message);
        byte[] publicKeyB = subtractPubKeys(virtualPublicKey, publicKeyA);
        if (validateSignatureSpecial(publicKeyB, randomPointB, signatureB, hash)) return null;

        byte[] signatureA = calculateSignature( pseudoRandomA, hash, secretKeyA);
        byte[] signature = addScalars(signatureA, signatureB);

        byte[] sing = new byte[signatureLength + message.length]; // TODO spelling
        for (i = 0; i < ScalarMult.groupElementLength; i ++) { sing[i] = randomPoint[i]; }
        for (i = 0; i < ScalarMult.scalarLength; i ++) { sing[ScalarMult.groupElementLength+i] = signature[i]; }
        for (i = 0; i < message.length; i ++) { sing[signatureLength+i] = message[i]; }
        return sing;
    }

    private static byte[] calculateRand(byte [] message, byte [] secretKey){

        byte[] rand = new byte[64]; // 64 instead of 32. Reduction in the end
        int i;
        byte [] tempBuffer = new byte[secretRandomLength + message.length];

        for (i = 0; i < secretRandomLength; i ++) tempBuffer[i] = secretKey[ScalarMult.scalarLength + i];
        for (i = 0; i < message.length; i ++) tempBuffer[secretRandomLength + i] = message[i];

        TweetNaclFast.crypto_hash(rand, tempBuffer,0, secretRandomLength + message.length);
        TweetNaclFast.reduce(rand);
        return rand;
    }

    private static byte[] calculateHash(byte [] randomPoint, byte [] publicKey, byte [] message){
        int i;
        byte[] hash = new byte[64]; // 64 instead of 32. Reduction in the end
        byte [] tempBuffer = new byte[ScalarMult.groupElementLength + publicKeyLength + message.length];
        for (i = 0; i < ScalarMult.groupElementLength; i ++) { tempBuffer[i] = randomPoint[i]; }
        for (i = 0; i < publicKeyLength; i ++) { tempBuffer[ScalarMult.groupElementLength+i] = publicKey[i]; }
        for (i = 0; i < message.length; i ++) { tempBuffer[ScalarMult.groupElementLength + publicKeyLength + i] = message[i]; }
        TweetNaclFast.crypto_hash(hash, tempBuffer,0, tempBuffer.length);
        TweetNaclFast.reduce(hash);
        return hash;
    }

    private static byte[] calculateSignature(byte [] rand, byte [] hash, byte [] secretKey){
        byte[] signature = new byte[ScalarMult.scalarLength];

        int i, j;
        long [] x = new long[64];
        for (i = 0; i < 64; i ++) x[i] = 0;
        for (i = 0; i < 32; i ++) x[i] = (long) (rand[i]&0xff);
        for (i = 0; i < 32; i ++) for (j = 0; j < 32; j ++) x[i+j] += (hash[i]&0xff) * (long) (secretKey[j]&0xff);
        TweetNaclFast.modL(signature,0, x);
        return signature;
    }

    private static boolean validateSignatureSpecial(byte[] publicKey, byte[] randomPoint, byte[] signature, byte[] hash) {
        long [] [] p = new long [4] [];
        p[0] = new long [16];
        p[1] = new long [16];
        p[2] = new long [16];
        p[3] = new long [16];

        long [] [] q = new long [4] [];
        q[0] = new long [16];
        q[1] = new long [16];
        q[2] = new long [16];
        q[3] = new long [16];

        byte[] t = new byte[ScalarMult.groupElementLength];

        if (TweetNaclFast.unpackneg(q, publicKey)!=0) return true;
        TweetNaclFast.scalarmult(p,q, hash,0);
        TweetNaclFast.scalarbase(q, signature,0);
        TweetNaclFast.add(p,q);
        TweetNaclFast.pack(t,p);
        return TweetNaclFast.crypto_verify_32(randomPoint, 0, t, 0) != 0;
    }

    // Encrypt and Decryption

    public static byte[] encrypt(byte[] message, byte[] nonce, byte[] toPublicKey, byte[] random){
        int i;
        byte[] tempPublicKey = new byte[publicKeyLength];
        byte[] tempSecretKey = new byte[secretKeyLength];
        byte[] pointAB = new byte[ScalarMult.groupElementLength];
        byte[] sharedKey = new byte[Box.sharedKeyLength];
        createKey(tempPublicKey, tempSecretKey, random);

        long[][] p = new long[4][];
        p[0] = new long[16];
        p[1] = new long[16];
        p[2] = new long[16];
        p[3] = new long[16];
        long[][] q = new long[4][];
        q[0] = new long[16];
        q[1] = new long[16];
        q[2] = new long[16];
        q[3] = new long[16];

        if (unpack(q, toPublicKey)!=0) return null;
        TweetNaclFast.scalarmult(p, q, tempSecretKey, 0);
        TweetNaclFast.pack(pointAB, p);
        TweetNaclFast.crypto_core_hsalsa20(sharedKey, TweetNaclFast._0, pointAB, TweetNaclFast.sigma);
        byte [] messageBuffer = new byte[Box.zerobytesLength+message.length];
        byte [] cipherText = new byte[messageBuffer.length];
        for (i = 0; i < message.length; i ++) messageBuffer[i+Box.zerobytesLength] = message[i];
        TweetNaclFast.crypto_box_afternm(cipherText, messageBuffer, messageBuffer.length, nonce, sharedKey);
        byte [] cipherMessage = new byte[cipherMessageHeaderLength +messageBuffer.length-Box.boxzerobytesLength];
        for (i = 0; i < nonceLength; i ++) { cipherMessage[i] = nonce[i]; }
        for (i = 0; i < publicKeyLength; i ++) { cipherMessage[i+nonceLength] = tempPublicKey[i]; }
        for (i = 0; i < messageBuffer.length-Box.boxzerobytesLength; i ++) {
            cipherMessage[i+ cipherMessageHeaderLength] = cipherText[Box.boxzerobytesLength+i];
        }
        return cipherMessage;
    }

    public static byte[] decrypt(byte[] cipherMessage, byte[] nonce, byte[] secretKey){
        int i;
        byte[] cipherText = new byte[cipherMessage.length- cipherMessageHeaderLength];
        for (i = 0; i < cipherText.length; i ++) { cipherText[i] = cipherMessage[i+ cipherMessageHeaderLength]; }
        for (i = 0; i < nonceLength; i ++) { nonce[i] = cipherMessage[i]; }

        byte[] pointAB = decryptDual1(cipherMessage, secretKey);
        return decryptMessage(cipherText, nonce, pointAB);
    }

    private static byte[] decryptMessage( byte[] cipherText, byte[] nonce, byte[] point) {
        byte[] sharedKey = new byte[Box.sharedKeyLength];
        int i;
        TweetNaclFast.crypto_core_hsalsa20(sharedKey, TweetNaclFast._0, point, TweetNaclFast.sigma);
        byte [] cipherBuffer = new byte[Box.boxzerobytesLength+cipherText.length];
        byte [] messageBuffer = new byte[cipherBuffer.length];
        for (i = 0; i < cipherText.length; i ++) cipherBuffer[i+Box.boxzerobytesLength] = cipherText[i];
        TweetNaclFast.crypto_box_open_afternm(messageBuffer, cipherBuffer, cipherBuffer.length, nonce, sharedKey);
        byte [] message = new byte[messageBuffer.length-Box.zerobytesLength];
        for (i = 0; i < message.length; i ++) message[i] = messageBuffer[i+Box.zerobytesLength];
        return message;
    }

    public static byte[] decryptDual1(byte[] cipherMessage, byte[] secretKey){
        int i;
        byte[] point = new byte[d1HeaderLength];
        byte[] tempPublicKey = new byte[publicKeyLength];
        for (i = 0; i < publicKeyLength; i ++) { tempPublicKey[i] = cipherMessage[i+nonceLength]; }

        long[][] p = new long[4][];
        p[0] = new long[16];
        p[1] = new long[16];
        p[2] = new long[16];
        p[3] = new long[16];
        long[][] q = new long[4][];
        q[0] = new long[16];
        q[1] = new long[16];
        q[2] = new long[16];
        q[3] = new long[16];

        if (unpack(q, tempPublicKey)!=0) return null;
        TweetNaclFast.scalarmult(p, q, secretKey, 0);
        TweetNaclFast.pack(point, p);
        return point;
    }

    public static byte[] decryptDual2(byte[] d1, byte[] cipherMessage, byte[] nonce, byte[] secretKey){
        int i;
        byte[] tempPublicKey = new byte[publicKeyLength];
        byte[] point = new byte[ScalarMult.groupElementLength];
        byte[] cipherText = new byte[cipherMessage.length- cipherMessageHeaderLength];
        for (i = 0; i < nonceLength; i ++) { nonce[i] = cipherMessage[i]; }
        for (i = 0; i < publicKeyLength; i ++) { tempPublicKey[i] = cipherMessage[i+nonceLength]; }
        for (i = 0; i < cipherText.length; i ++) { cipherText[i] = cipherMessage[i+ cipherMessageHeaderLength]; }

        long[][] p = new long[4][];
        p[0] = new long[16];
        p[1] = new long[16];
        p[2] = new long[16];
        p[3] = new long[16];
        long[][] q = new long[4][];
        q[0] = new long[16];
        q[1] = new long[16];
        q[2] = new long[16];
        q[3] = new long[16];

        if (unpack(q, tempPublicKey)!=0) return null;
        TweetNaclFast.scalarmult(p, q, secretKey, 0);

        if (unpack(q, d1)!=0) return null;
        TweetNaclFast.add(p, q);
        TweetNaclFast.pack(point, p);

        return decryptMessage(cipherText, nonce, point);
    }
}
