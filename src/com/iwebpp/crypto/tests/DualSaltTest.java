package com.iwebpp.crypto.tests;

import com.iwebpp.crypto.DualSalt;
import com.iwebpp.crypto.TweetNaclFast;

import java.util.Arrays;

public class DualSaltTest {

    private static final String TAG = "DualSaltTest";

    private void testKeyAddition(byte[] secKeyA, byte[] secKeyB){
        System.out.println("\nTest key addition");
        byte[] pubKeyA = new byte[32];
        byte[] pubKeyB = new byte[32];
        DualSalt.createKey(pubKeyA, secKeyA, null, true);
        DualSalt.createKey(pubKeyB, secKeyB, null, true);

        Log.d( TAG, "A public key: " + TweetNaclFast.hexEncodeToString(pubKeyA));
        Log.d( TAG, "B public key: " + TweetNaclFast.hexEncodeToString(pubKeyB));
        byte[] pubKeyAB1 = DualSalt.addPoints(pubKeyA, pubKeyB);
        if (pubKeyAB1 == null){
            Log.d( TAG, "Fail, Could not add keys");
            return;
        }
        Log.d( TAG, "Group public key 1: " + TweetNaclFast.hexEncodeToString(pubKeyAB1));

        byte[] pubKeyAB2 = new byte[32];
        byte[] secKeyAB = DualSalt.addScalars(secKeyA, secKeyB);
        DualSalt.createKey(pubKeyAB2, secKeyAB, null, true);
        Log.d( TAG, "Group public key 2: " + TweetNaclFast.hexEncodeToString(pubKeyAB2));
        Log.d( TAG, "Group public key ok: " + Arrays.equals( pubKeyAB1, pubKeyAB2));
    }

    public void start() {
        (new Thread(new Runnable() {
            public void run() {
                Log.d(TAG, "start test");

                byte[] rand1 = TweetNaclFast.hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
                byte[] rand2 = TweetNaclFast.hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
                byte[] rand3 = TweetNaclFast.hexDecode("995afd8c14adb49410ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4");

                byte[] pubKeyA = new byte[32];
                byte[] pubKeyB = new byte[32];
                byte[] pubKeyC = new byte[32];

                byte[] secKeyA = new byte[64];
                byte[] secKeyB = new byte[64];
                byte[] secKeyC = new byte[64];

                DualSalt.createKey(pubKeyA, secKeyA, rand1, false);
                DualSalt.createKey(pubKeyB, secKeyB, rand2, false);
                DualSalt.createKey(pubKeyC, secKeyC, rand3, false);

                testKeyAddition(secKeyA, secKeyB);
                testKeyAddition(secKeyA, secKeyC);
                testKeyAddition(secKeyB, secKeyC);

            }
        })).start();

    }

    public static void main(String[] args) {
        DualSaltTest t = new DualSaltTest();
        t.start();
    }
}
