package com.iwebpp.crypto.tests;

import com.iwebpp.crypto.DualSalt;
import com.iwebpp.crypto.TweetNaclFast;

import java.util.Arrays;

public class DualSaltTest {

    private static final String TAG = "DualSaltTest";

    private void testKeyAddition(byte[] rand1, byte[] rand2){
        System.out.println("\nTest key addition");

        byte[] pubKeyA = new byte[32];
        byte[] pubKeyB = new byte[32];
        byte[] secKeyA = new byte[64];
        byte[] secKeyB = new byte[64];
        DualSalt.createKey(pubKeyA, secKeyA, rand1);
        DualSalt.createKey(pubKeyB, secKeyB, rand2);

        Log.d( TAG, "A public key: " + TweetNaclFast.hexEncodeToString(pubKeyA));
        Log.d( TAG, "B public key: " + TweetNaclFast.hexEncodeToString(pubKeyB));
        byte[] pubKeyAB1 = DualSalt.addPoints(pubKeyA, pubKeyB);
        if (pubKeyAB1 == null){
            Log.d( TAG, "Fail, Could not add keys");
            return;
        }
        Log.d( TAG, "Group public key 1: " + TweetNaclFast.hexEncodeToString(pubKeyAB1));


        byte[] secKeyAB = DualSalt.addScalars(secKeyA, secKeyB);
        byte[] pubKeyAB2 = DualSalt.calculatePubKey(secKeyAB);
        Log.d( TAG, "Group public key 2: " + TweetNaclFast.hexEncodeToString(pubKeyAB2));
        Log.d( TAG, "Group public key ok: " + Arrays.equals( pubKeyAB1, pubKeyAB2));
    }

    private void testRotateKeys(byte[] rand1, byte[] rand2, byte[] rand3) throws Exception {
        System.out.println("\nTest rotate keys");

        byte[] pubKeyA = new byte[32];
        byte[] pubKeyB = new byte[32];
        byte[] secKeyA = new byte[64];
        byte[] secKeyB = new byte[64];
        DualSalt.createKey(pubKeyA, secKeyA, rand1);
        DualSalt.createKey(pubKeyB, secKeyB, rand2);

        byte[] pubKeyAB1 = DualSalt.addPoints(pubKeyA, pubKeyB);
        if (pubKeyAB1 == null){
            Log.d( TAG, "Fail, Could not add keys");
            throw new Exception();
        }

        byte[] pubKeyA2 = new byte[32];
        byte[] pubKeyB2 = new byte[32];
        DualSalt.rotateKey(pubKeyA2, secKeyA, rand3, true, new byte[32]);
        DualSalt.rotateKey(pubKeyB2, secKeyB, rand3, false, new byte[32]);

        if (Arrays.equals(pubKeyA, pubKeyB) ||
                Arrays.equals(pubKeyA, pubKeyA2) ||
                Arrays.equals(pubKeyA, pubKeyB2) ||
                Arrays.equals(pubKeyB, pubKeyA2) ||
                Arrays.equals(pubKeyB, pubKeyB2) ||
                Arrays.equals(pubKeyA2, pubKeyB2)) {
            Log.d(TAG, "A2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "B2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d( TAG, "Fail, Some pub keys was the same");
            throw new Exception();
        }


        byte[] pubKeyAB2 = DualSalt.addPoints(pubKeyA2, pubKeyB2);
        if (pubKeyAB2 == null){
            Log.d( TAG, "Fail, Could not add keys");
            throw new Exception();
        }

        if (Arrays.equals(pubKeyAB1, pubKeyAB2)){
            Log.d(TAG, "Success! The rotated virtual key has the same pub key");
        }
        else {
            Log.d(TAG, "A2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "B2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Fail, The rotated virtual key did not produce the same pub key ");
            throw new Exception();
        }
    }

    private void testDistributedDecryptionStress(int iterations) throws Exception {
        System.out.println("\nTest distributed decryption stress");

        for (int index= 0; index<iterations; index++) {
            byte[] rand1 = new byte[32];
            byte[] rand2 = new byte[32];
            byte[] rand3 = new byte[32];
            TweetNaclFast.randombytes(rand1,32);
            TweetNaclFast.randombytes(rand2,32);
            TweetNaclFast.randombytes(rand3,32);
            testRotateKeys(rand1, rand2, rand3);
        }
    }

    private void start() {
        (new Thread(() -> {
            Log.d(TAG, "start test");

            try {
                byte[] rand1 = TweetNaclFast.hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
                byte[] rand2 = TweetNaclFast.hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
                byte[] rand3 = TweetNaclFast.hexDecode("995afd8c14adb49410ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4");

                testKeyAddition(rand1, rand2);
                testKeyAddition(rand1, rand3);
                testKeyAddition(rand2, rand3);

                testRotateKeys(rand1, rand2, rand3);
                testRotateKeys(rand1, rand3, rand2);
                testRotateKeys(rand2, rand3, rand1);

                testDistributedDecryptionStress(1000);

            } catch (Exception e) {
                e.printStackTrace();
            }


        })).start();

    }

    public static void main(String[] args) {
        DualSaltTest t = new DualSaltTest();
        t.start();
    }
}
