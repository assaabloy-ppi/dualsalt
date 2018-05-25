package dualsalt.tests;

import dualsalt.DualSalt;
import dualsalt.TweetNaclFast;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.Scanner;

public class DualSaltTest {

    private static final String TAG = "DualSaltTest";

    private static byte[] addScalars(byte[] scalarA, byte[] scalarB) {
        // Copy of addScalars() in DualSalt to be able to have that function
        // private
        int i;
        byte[] scalar = new byte[TweetNaclFast.ScalarMult.scalarLength];
        long[] temp = new long[64];
        for (i = 0; i < 64; i++)
            temp[i] = 0;
        for (i = 0; i < 32; i++)
            temp[i] = (long) (scalarA[i] & 0xff);
        for (i = 0; i < 32; i++)
            temp[i] += (long) (scalarB[i] & 0xff);

        TweetNaclFast.modL(scalar, 0, temp);

        return scalar;
    }

    private void testKeyAddition(byte[] rand1, byte[] rand2) throws Exception {
        System.out.println("\nTest key addition");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);

        byte[] pubKeyAB1 = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] secScalarAB = addScalars(secKeyA, secKeyB);
        byte[] secSecAB = new byte[DualSalt.secretKeyLength];
        System.arraycopy(secScalarAB, 0, secSecAB, 0, TweetNaclFast.ScalarMult.scalarLength);
        byte[] pubKeyAB2 = DualSalt.calculatePublicKey(secSecAB);

        if (Arrays.equals(pubKeyAB1, pubKeyAB2)) {
            Log.d(TAG, "Group public key ok");
        } else {
            Log.d(TAG, "Rand1: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "Rand2: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d(TAG, "Group public key 1: " + TweetNaclFast.hexEncodeToString(pubKeyAB1));
            Log.d(TAG, "Group public key 2: " + TweetNaclFast.hexEncodeToString(pubKeyAB2));
            throw new Exception();
        }
    }

    static void testRotateKeys(byte[] rand1, byte[] rand2, byte[] rand3) throws Exception {
        System.out.println("\nTest rotate keys");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] oldSecRandA = Arrays.copyOfRange(secKeyA, 32, DualSalt.secretKeyLength);
        byte[] oldSecRandB = Arrays.copyOfRange(secKeyB, 32, DualSalt.secretKeyLength);

        byte[] pubKeyAB1 = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] pubKeyA2 = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB2 = new byte[DualSalt.publicKeyLength];
        DualSalt.rotateKey(pubKeyA2, secKeyA, rand3, true);
        DualSalt.rotateKey(pubKeyB2, secKeyB, rand3, false);

        if (Arrays.equals(pubKeyA, pubKeyB) || Arrays.equals(pubKeyA, pubKeyA2)
                || Arrays.equals(pubKeyA, pubKeyB2) || Arrays.equals(pubKeyB, pubKeyA2)
                || Arrays.equals(pubKeyB, pubKeyB2) || Arrays.equals(pubKeyA2, pubKeyB2)) {
            Log.d(TAG, "A2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "B2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Fail, Some pub keys was the same");
            throw new Exception();
        }

        byte[] newSecRandA = Arrays.copyOfRange(secKeyA, 32, DualSalt.secretKeyLength);
        byte[] newSecRandB = Arrays.copyOfRange(secKeyB, 32, DualSalt.secretKeyLength);
        if (Arrays.equals(oldSecRandA, newSecRandA) || Arrays.equals(oldSecRandB, newSecRandB)
                || Arrays.equals(newSecRandA, newSecRandB)) {
            Log.d(TAG, "A2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "B2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Fail, The secret random part has not changed correctly");
            throw new Exception();
        }

        byte[] pubKeyAB2 = DualSalt.addPublicKeys(pubKeyA2, pubKeyB2);

        if (Arrays.equals(pubKeyAB1, pubKeyAB2)) {
            Log.d(TAG, "Success! The rotated virtual key has the same pub key");
        } else {
            Log.d(TAG, "A2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "B2 secret key: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Fail, The rotated virtual key did not produce the same pub key ");
            throw new Exception();
        }
    }

    private void testSingleSign(byte[] rand, String testString) throws Exception {
        System.out.println("\nTest single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(publicKey, secretKey, rand);
        byte[] message = testString.getBytes();

        byte[] signature = DualSalt.signCreate(message, publicKey, secretKey);

        if (DualSalt.signVerify(signature, publicKey)) {
            Log.d(TAG, "Verified signature succeeded");
        } else {
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Verified signature failed");
            throw new Exception();
        }
    }

    private void testNegativeSingleSign(byte[] rand, String testString) throws Exception {
        System.out.println("\nTest negative single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(publicKey, secretKey, rand);
        byte[] message = testString.getBytes();

        byte[] signature = DualSalt.signCreate(message, publicKey, secretKey);

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((signature.length - 1) * i) / steps;
            byte[] tempSignature = signature.clone();
            tempSignature[j] = (byte) (tempSignature[j] ^ 0x1);
            if (DualSalt.signVerify(tempSignature, publicKey)) {
                Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Validated succeeded but it should not");
                throw new Exception();
            }
        }

        for (int i = 0; i <= steps; i++) {
            int j = ((publicKey.length - 1) * i) / steps;
            byte[] tempPublicKey = publicKey.clone();
            tempPublicKey[j] = (byte) (tempPublicKey[j] ^ 0x1);
            if (DualSalt.signVerify(signature, tempPublicKey)) {
                Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Validated succeeded but it should not");
                throw new Exception();
            }
        }

        Log.d(TAG, "Signature validation fail when it shall");
    }

    private void testSubtractPubKey(byte[] rand1, byte[] rand2) throws Exception {
        System.out.println("\nTest subtract pub key");
        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] pubKeyC = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
        byte[] pubKeyA2 = DualSalt.subtractPublicKeys(pubKeyC, pubKeyB);
        byte[] pubKeyB2 = DualSalt.subtractPublicKeys(pubKeyC, pubKeyA);
        if (Arrays.equals(pubKeyA, pubKeyA2) && Arrays.equals(pubKeyB, pubKeyB2)) {
            Log.d(TAG, "Success! The add and subtract did produce the same public key");
        } else {
            Log.d(TAG, "Random 1 key: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Random 2 key: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Fail, The add and subtract did not produce the same public key");
            throw new Exception();
        }
    }

    static void testDualSign(byte[] rand1, byte[] rand2, String testString) throws Exception {
        System.out.println("\nTest dual sign");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] message = testString.getBytes();

        byte[] virtualPublicKey = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB);
        byte[] signature = DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);

        if (DualSalt.signVerify(signature, virtualPublicKey)) {
            Log.d(TAG, "Verified signature succeeded");
        } else {
            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Verified signature failed");
            throw new Exception();
        }
    }

    private static void testNegativeDualSign(byte[] rand1, byte[] rand2, String testString)
            throws Exception {
        System.out.println("\nTest negative dual sign");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] message = testString.getBytes();

        byte[] virtualPublicKey = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB);

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((m2.length - 1) * i) / steps;
            byte[] tempM2 = m2.clone();
            tempM2[j] = (byte) (tempM2[j] ^ 0x1);
            try {
                DualSalt.signCreateDual3(m1, tempM2, pubKeyA, secKeyA);
                Log.d(TAG, "Rand1: " + TweetNaclFast.hexEncodeToString(rand1));
                Log.d(TAG, "Rand2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Validated succeeded but it should not");
                throw new Exception();
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        for (int i = 0; i <= steps; i++) {
            int j = ((pubKeyA.length - 1) * i) / steps;
            byte[] tempPubKeyA = pubKeyA.clone();
            tempPubKeyA[j] = (byte) (tempPubKeyA[j] ^ 0x1);
            try {
                DualSalt.signCreateDual3(m1, m2, tempPubKeyA, secKeyA);
                Log.d(TAG, "Rand1: " + TweetNaclFast.hexEncodeToString(rand1));
                Log.d(TAG, "Rand2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Validated succeeded but it should not");
                throw new Exception();
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        Log.d(TAG, "Signature validation fail when it shall");
    }

    static void testSingleDecrypt(byte[] rand1, byte[] rand2, byte[] rand3, String testString)
            throws Exception {
        System.out.println("\nTest single decrypt");

        byte[] nonce = new byte[DualSalt.nonceLength];
        byte[] pubKey = new byte[DualSalt.publicKeyLength];
        byte[] secKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKey, secKey, rand1);
        byte[] message = testString.getBytes();

        byte[] cipherMessage = DualSalt.encrypt(message, rand2, pubKey, rand3);
        Log.d(TAG, "Cipher message:  " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] decryptedMessage = DualSalt.decrypt(cipherMessage, nonce, secKey);

        if (Arrays.equals(rand2, nonce) && Arrays.equals(message, decryptedMessage)) {
            Log.d(TAG, "Decrypt message succeeded");
        } else {

            Log.d(TAG, "Nonce:  " + TweetNaclFast.hexEncodeToString(nonce));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Message:  " + TweetNaclFast.hexEncodeToString(message));
            Log.d(TAG, "DMessage: " + TweetNaclFast.hexEncodeToString(decryptedMessage));

            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Decrypt message failed");
            throw new Exception();
        }
    }

    private static void testNegativeSingleDecrypt(byte[] rand1, byte[] rand2, byte[] rand3,
            String testString) throws Exception {
        System.out.println("\nTest negative single decrypt");

        byte[] nonce = new byte[DualSalt.nonceLength];
        byte[] pubKey = new byte[DualSalt.publicKeyLength];
        byte[] secKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKey, secKey, rand1);
        byte[] message = testString.getBytes();

        byte[] cipherMessage = DualSalt.encrypt(message, rand2, pubKey, rand3);
        Log.d(TAG, "Cipher message:  " + TweetNaclFast.hexEncodeToString(cipherMessage));

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((cipherMessage.length - 1) * i) / steps;
            byte[] tempCipherMessage = cipherMessage.clone();
            tempCipherMessage[j] = (byte) (tempCipherMessage[j] ^ 0x1);
            try {
                DualSalt.decrypt(tempCipherMessage, nonce, secKey);
                Log.d(TAG, "Nonce:  " + TweetNaclFast.hexEncodeToString(nonce));
                Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Message:  " + TweetNaclFast.hexEncodeToString(message));

                Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
                Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Decryption succeeded but it should not");
                throw new Exception();
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        Log.d(TAG, "Message decryption validation fail when it shall");
    }

    static void testDualDecrypt(byte[] rand1, byte[] rand2, byte[] rand3, byte[] rand4,
            String testString) throws Exception {
        System.out.println("\nTest dual decrypt");

        byte[] nonce = new byte[DualSalt.nonceLength];
        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] pubKeyAB = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
        byte[] message = testString.getBytes();

        byte[] cipherMessage = DualSalt.encrypt(message, rand3, pubKeyAB, rand4);
        Log.d(TAG, "Cipher message: " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
        byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, nonce, secKeyB);
        if (Arrays.equals(rand3, nonce) && Arrays.equals(message, decryptedMessage)) {
            Log.d(TAG, "Decrypt message succeeded");
        } else {

            Log.d(TAG, "Nonce:  " + TweetNaclFast.hexEncodeToString(nonce));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Message:  " + TweetNaclFast.hexEncodeToString(message));
            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand4));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Decrypt message failed");
            throw new Exception();
        }
    }

    private static void testNegativeDualDecrypt(byte[] rand1, byte[] rand2, byte[] rand3,
            byte[] rand4, String testString) throws Exception {
        System.out.println("\nTest negative dual decrypt");

        byte[] nonce = new byte[DualSalt.nonceLength];
        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] pubKeyAB = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
        byte[] message = testString.getBytes();

        byte[] cipherMessage = DualSalt.encrypt(message, rand3, pubKeyAB, rand4);
        Log.d(TAG, "Cipher message: " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((cipherMessage.length - 1) * i) / steps;
            byte[] tempCipherMessage = cipherMessage.clone();
            tempCipherMessage[j] = (byte) (tempCipherMessage[j] ^ 0x1);
            try {
                DualSalt.decryptDual2(d1, tempCipherMessage, nonce, secKeyB);
                Log.d(TAG, "Nonce:  " + TweetNaclFast.hexEncodeToString(nonce));
                Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Message:  " + TweetNaclFast.hexEncodeToString(message));

                Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
                Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Decryption succeeded but it should not");
                throw new Exception();
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        for (int i = 0; i <= steps; i++) {
            int j = ((d1.length - 1) * i) / steps;
            byte[] tempD1 = d1.clone();
            tempD1[j] = (byte) (tempD1[j] ^ 0x1);
            try {
                DualSalt.decryptDual2(tempD1, cipherMessage, nonce, secKeyB);
                Log.d(TAG, "Nonce:  " + TweetNaclFast.hexEncodeToString(nonce));
                Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Message:  " + TweetNaclFast.hexEncodeToString(message));

                Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
                Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
                Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
                Log.d(TAG, "Test string: \"" + testString + "\"");
                Log.d(TAG, "Decryption succeeded but it should not");
                throw new Exception();
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        Log.d(TAG, "Message decryption validation fail when it shall");
    }

    private static void testEddsaTestVector() throws Exception {
        System.out.println("\nTest EdDSA test vector");

        String fileName = "sign.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutSecretKey = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicKey = TweetNaclFast.hexDecode(items[1]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[2]);
                byte[] dutSignature = TweetNaclFast.hexDecode(items[3]);

                byte[] secretKeySeed = Arrays.copyOfRange(dutSecretKey, 0, DualSalt.seedLength);
                byte[] secretKey = new byte[DualSalt.secretKeyLength];
                byte[] publicKey = new byte[DualSalt.publicKeyLength];
                DualSalt.createKeyPair(publicKey, secretKey, secretKeySeed);
                if (!Arrays.equals(dutPublicKey, publicKey)) {
                    throw new Exception("Public key do not match");
                }

                byte[] signature = DualSalt.signCreate(dutMessage, publicKey, secretKey);
                if (!DualSalt.signVerify(signature, publicKey)) {
                    throw new Exception("Signature do not verify correctly");
                }
                if (!Arrays.equals(dutSignature, signature)) {
                    throw new Exception("Signature do not match");
                }
            }
        }

        Log.d(TAG, "Test succeeded");
    }

    private void run() {
        try {
            byte[] rand1 = TweetNaclFast
                    .hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
            byte[] rand2 = TweetNaclFast
                    .hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
            byte[] rand3 = TweetNaclFast
                    .hexDecode("995afd8c14adb49410ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4");
            byte[] nonce = TweetNaclFast
                    .hexDecode("10ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4");

            testKeyAddition(rand1, rand2);
            testKeyAddition(rand1, rand3);
            testKeyAddition(rand2, rand3);

            testRotateKeys(rand1, rand2, rand3);
            testRotateKeys(rand1, rand3, rand2);
            testRotateKeys(rand2, rand3, rand1);

            testSingleSign(rand1, "The best signature in the world");
            testSingleSign(rand2, "The best signature in the all the worlds, You know like all all");
            testSingleSign(rand3,
                    "There could be only one ultimate signature and this is it. Stop arguing");

            testSubtractPubKey(rand1, rand2);
            testSubtractPubKey(rand1, rand3);
            testSubtractPubKey(rand2, rand3);

            testDualSign(rand1, rand2, "The best signature in the world");
            testDualSign(rand1, rand3,
                    "The best signature in the all the worlds, You know like all all");
            testDualSign(rand2, rand3,
                    "There could be only one ultimate signature and this is it. Stop arguing");

            testSingleDecrypt(rand1, nonce, rand2, "The best decryption in the world");
            testSingleDecrypt(rand1, nonce, rand3,
                    "The best decryption in the all the worlds, You know like all all");
            testSingleDecrypt(rand2, nonce, rand3,
                    "There could be only one ultimate decryption and this is it. Stop arguing");

            testDualDecrypt(rand1, rand2, nonce, rand3, "The best decryption in the world");
            testDualDecrypt(rand3, rand1, nonce, rand2,
                    "The best decryption in the all the worlds, You know like all all");
            testDualDecrypt(rand2, rand3, nonce, rand1,
                    "There could be only one ultimate decryption and this is it. Stop arguing");

            testEddsaTestVector();

            testNegativeSingleSign(rand1, "The best signature in the world");
            testNegativeSingleSign(rand2,
                    "The best signature in the all the worlds, You know like all all");
            testNegativeSingleSign(rand3,
                    "There could be only one ultimate signature and this is it. Stop arguing");

            testNegativeDualSign(rand1, rand2, "The best signature in the world");
            testNegativeDualSign(rand1, rand3,
                    "The best signature in the all the worlds, You know like all all");
            testNegativeDualSign(rand2, rand3,
                    "There could be only one ultimate signature and this is it. Stop arguing");

            testNegativeSingleDecrypt(rand1, nonce, rand2, "The best decryption in the world");
            testNegativeSingleDecrypt(rand1, nonce, rand3,
                    "The best decryption in the all the worlds, You know like all all");
            testNegativeSingleDecrypt(rand2, nonce, rand3,
                    "There could be only one ultimate decryption and this is it. Stop arguing");

            testNegativeDualDecrypt(rand1, rand2, nonce, rand3, "The best decryption in the world");
            testNegativeDualDecrypt(rand3, rand1, nonce, rand2,
                    "The best decryption in the all the worlds, You know like all all");
            testNegativeDualDecrypt(rand2, rand3, nonce, rand1,
                    "There could be only one ultimate decryption and this is it. Stop arguing");

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        System.out.println("\nSUCCESS! All tests passed.");
    }

    public static void main(String[] args) {
        DualSaltTest t = new DualSaltTest();
        t.run();
    }
}
