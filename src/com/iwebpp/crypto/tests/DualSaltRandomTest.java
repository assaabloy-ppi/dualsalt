package com.iwebpp.crypto.tests;

import com.iwebpp.crypto.TweetNaclFast;

public class DualSaltRandomTest {

    private static final String TAG = "DualSaltRandomTest";

    private void testRotateKeysRandom() throws Exception {
        System.out.println("\nTest rotate keys random");

        for (int index = 0; index< 1000; index++) {
            byte[] rand1 = new byte[32];
            byte[] rand2 = new byte[32];
            byte[] rand3 = new byte[32];
            TweetNaclFast.randombytes(rand1,32);
            TweetNaclFast.randombytes(rand2,32);
            TweetNaclFast.randombytes(rand3,32);
            DualSaltTest.testRotateKeys(rand1, rand2, rand3);
        }
    }

    private void testDualSignRandom() throws Exception {
        System.out.println("\nTest dual sign random");

        for (int index = 0; index< 1000; index++) {
            byte[] rand1 = new byte[32];
            byte[] rand2 = new byte[32];
            TweetNaclFast.randombytes(rand1,32);
            TweetNaclFast.randombytes(rand2,32);
            DualSaltTest.testDualSign(rand1, rand2, "Sen vart det bara en tummetott");
        }
    }

    private void testSingleDecryptRandom() throws Exception {
        System.out.println("\nTest dual sign random");

        for (int index = 0; index< 1000; index++) {
            byte[] rand1 = new byte[32];
            byte[] rand2 = new byte[24];
            byte[] rand3 = new byte[32];
            TweetNaclFast.randombytes(rand1,32);
            TweetNaclFast.randombytes(rand2,24);
            TweetNaclFast.randombytes(rand3,32);
            DualSaltTest.testSingleDecrypt(rand1, rand2, rand3, "Sen vart det bara en tummetott");
        }
    }

    private void testDualDecryptRandom() throws Exception {
        System.out.println("\nTest dual decrypt random");

        for (int index = 0; index< 1000; index++) {
            byte[] rand1 = new byte[32];
            byte[] rand2 = new byte[32];
            byte[] rand3 = new byte[24];
            byte[] rand4 = new byte[32];
            TweetNaclFast.randombytes(rand1,32);
            TweetNaclFast.randombytes(rand2,32);
            TweetNaclFast.randombytes(rand3,24);
            TweetNaclFast.randombytes(rand4,32);
            DualSaltTest.testDualDecrypt(rand1, rand2, rand3, rand4, "Sen vart det bara en tummetott");
        }
    }

    private void start() {
        (new Thread(() -> {
            Log.d(TAG, "start test");

            try {
                testRotateKeysRandom();
                testDualSignRandom();
                testSingleDecryptRandom();
                testDualDecryptRandom();

            } catch (Exception e) {
                e.printStackTrace();
            }


        })).start();

    }

    public static void main(String[] args) {
        DualSaltRandomTest t = new DualSaltRandomTest();
        t.start();
    }
}