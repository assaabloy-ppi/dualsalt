package com.iwebpp.crypto;

public class DualSalt {
    public static void createKey(byte[] publicKey, byte[] secretKey, byte[] random){
        int i;
        TweetNaclFast.crypto_hash(secretKey, random, 0, 32);
        secretKey[0] &= 248;
        secretKey[31] &= 127;
        secretKey[31] |= 64;
        byte[] tempPublicKey = calculatePubKey(secretKey);

        for (i = 0; i < 32; i ++) publicKey[i] = tempPublicKey[i];
    }

    public static byte[] calculatePubKey(byte[] secretKey){
        byte[] publicKey = new byte[32];
        long [] [] p = new long [4] [];
        p[0] = new long [16];
        p[1] = new long [16];
        p[2] = new long [16];
        p[3] = new long [16];
        TweetNaclFast.scalarbase(p, secretKey, 0);
        TweetNaclFast.pack(publicKey, p);
        return publicKey;
    }

    public static void rotateKey(byte[] publicKey, byte[] secretKey, byte[] random1, boolean first, byte[] random2){
        byte[] newScalar;
        int i;
        if (first){
            newScalar = addScalars(secretKey, random1);
        } else {
            newScalar = subtractScalars(secretKey, random1);
        }
        for (i = 0; i < 32; i ++) secretKey[i] = newScalar[i];
        for (i = 0; i < 32; i ++) secretKey[32+i] = random2[i];
        byte[] tempPublicKey = calculatePubKey(secretKey);
        for (i = 0; i < 32; i ++) publicKey[i] = tempPublicKey[i];
    }

    public static byte[] addScalars(byte[] scalarA, byte[] scalarB){
        int i;
        byte[] scalar = new byte[32];
        long[] temp = new long[64];
        for (i = 0; i < 64; i ++) temp[i] = 0;
        for (i = 0; i < 32; i ++) temp[i] = (long) (scalarA[i]&0xff);
        for (i = 0; i < 32; i ++) temp[i] += (long) (scalarB[i]&0xff);

        TweetNaclFast.modL(scalar,0, temp);

        return scalar;
    }

    private static byte[] subtractScalars(byte[] scalarA, byte[] scalarB){
        int i;
        byte[] scalar = new byte[32];
        long[] temp = new long[64];
        for (i = 0; i < 64; i ++) temp[i] = 0;
        for (i = 0; i < 32; i ++) temp[i] = (long) (scalarA[i]&0xff);
        for (i = 0; i < 32; i ++) temp[i] -= (long) (scalarB[i]&0xff);

        TweetNaclFast.modL(scalar,0, temp);

        return scalar;
    }
    public static byte[] addPubKeys(byte[] pointA, byte[] pointB){
        long [] [] a = new long [4] [];
        a[0] = new long [16];
        a[1] = new long [16];
        a[2] = new long [16];
        a[3] = new long [16];

        long [] [] b = new long [4] [];
        b[0] = new long [16];
        b[1] = new long [16];
        b[2] = new long [16];
        b[3] = new long [16];
        if (unpack(a, pointA) != 0) return null;
        if (unpack(b, pointB) != 0) return null;

        TweetNaclFast.add(a,b);

        byte[] pointR = new byte[32];
        TweetNaclFast.pack(pointR, a);

        return pointR;
    }

    private static int unpack(long[] r[], byte p[])
    {
        long []    t = new long [16];
        long []  chk = new long [16];
        long []  num = new long [16];
        long []  den = new long [16];
        long [] den2 = new long [16];
        long [] den4 = new long [16];
        long [] den6 = new long [16];
        // r[0]=x    r[1]=y   r[2]=z    r[3]=t

        TweetNaclFast.set25519(r[2], TweetNaclFast.gf1);
        TweetNaclFast.unpack25519(r[1], p);
        TweetNaclFast.S(num, r[1]);
        TweetNaclFast.M(den, num, TweetNaclFast.D);
        TweetNaclFast.Z(num, num, r[2]);
        TweetNaclFast.A(den, r[2], den);

        TweetNaclFast.S(den2, den);
        TweetNaclFast.S(den4, den2);
        TweetNaclFast.M(den6, den4, den2);
        TweetNaclFast.M(t, den6, num);
        TweetNaclFast.M(t, t, den);

        TweetNaclFast.pow2523(t, t);
        TweetNaclFast.M(t, t, num);
        TweetNaclFast.M(t, t, den);
        TweetNaclFast.M(t, t, den);
        TweetNaclFast.M(r[0], t, den);

        TweetNaclFast.S(chk, r[0]);
        TweetNaclFast.M(chk, chk, den);
        if (TweetNaclFast.neq25519(chk, num)!=0) TweetNaclFast.M(r[0], r[0], TweetNaclFast.I);

        TweetNaclFast.S(chk, r[0]);
        TweetNaclFast.M(chk, chk, den);
        if (TweetNaclFast.neq25519(chk, num)!=0) return -1;

        if (TweetNaclFast.par25519(r[0]) != ((p[31]&0xFF)>>>7)) TweetNaclFast.Z(r[0], TweetNaclFast.gf0, r[0]);

        TweetNaclFast.M(r[3], r[0], r[1]);

        return 0;
    }

// Signing

// M1 = sign1(m, C, a)
// M2 = sign2(M1, b)
// (R,s) = sign3(M1, M2, a)
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
    }

(R, s) = sign(m, a, A){
        (ar, ad) = a
                r = H(ar||m)
        R = r*P
        h = H(R||A||m)
        s = r + h*ad
        return (R, s)
    }

    bool verify((R,a), A){
        return R == h*A + s*P
    }

// Encrypt and Decryption

    D1 = decrypt1(CT, a){
        (PKx, c) = CT
        return a(0:31)*PKx
    }

(msg, nonce) = decrypt2(CT, D1, b){
        (PKx, c) = CT
                share = b(0:31)*PKx + D1
        return symetricCrypto(share, c)
    }

(msg, nonce) = decrypt(CT, a){
        (PKx, c) = CT
                share = a(0:31)*PKx
        return symetricCrypto(share, c)
    }

    CT = encrypt(msg, nonce, toPub, rand){
        createKey(PK, sk, rand, false)
        share = sk(0:31)*toPub
        return (PK, symetricCrypto(share, msg, nonce))
    }
    */
}
