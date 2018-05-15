package dualsalt.tests;

import dualsalt.DualSalt;
import dualsalt.TweetNaclFast;

import java.util.Arrays;

public class DualSaltTest {

    private static final String TAG = "DualSaltTest";

    private void testKeyAddition(byte[] rand1, byte[] rand2) throws Exception {
        System.out.println("\nTest key addition");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);

        byte[] pubKeyAB1 = DualSalt.addPubKeys(pubKeyA, pubKeyB);
        if (pubKeyAB1 == null){
            Log.d(TAG, "Rand1: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "Rand2: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d( TAG, "Fail, Could not add keys");
            throw new Exception();
        }

        byte[] secScalarAB = DualSalt.addScalars(secKeyA, secKeyB);
        byte[] secSecAB = new byte[DualSalt.secretKeyLength];
        System.arraycopy(secScalarAB, 0, secSecAB, 0, TweetNaclFast.ScalarMult.scalarLength);
        byte[] pubKeyAB2 = DualSalt.calculatePublicKey(secSecAB);

        if (Arrays.equals(pubKeyAB1, pubKeyAB2)) {
            Log.d( TAG, "Group public key ok");
        } else {
            Log.d(TAG, "Rand1: " + TweetNaclFast.hexEncodeToString(secKeyA));
            Log.d(TAG, "Rand2: " + TweetNaclFast.hexEncodeToString(secKeyB));
            Log.d( TAG, "Group public key 1: " + TweetNaclFast.hexEncodeToString(pubKeyAB1));
            Log.d( TAG, "Group public key 2: " + TweetNaclFast.hexEncodeToString(pubKeyAB2));
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

        byte[] pubKeyAB1 = DualSalt.addPubKeys(pubKeyA, pubKeyB);
        if (pubKeyAB1 == null){
            Log.d( TAG, "Fail, Could not add keys");
            throw new Exception();
        }

        byte[] pubKeyA2 = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB2 = new byte[DualSalt.publicKeyLength];
        DualSalt.rotateKey(pubKeyA2, secKeyA, rand3, true, new byte[DualSalt.seedLength]);
        DualSalt.rotateKey(pubKeyB2, secKeyB, rand3, false, new byte[DualSalt.seedLength]);

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


        byte[] pubKeyAB2 = DualSalt.addPubKeys(pubKeyA2, pubKeyB2);
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

    private void testSingleSign(byte[] rand, String testString ) throws Exception {
        System.out.println("\nTest single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(publicKey, secretKey, rand);
        byte[] message = testString.getBytes();

        byte[] signature = new byte[DualSalt.signatureLength+message.length];
        DualSalt.signCreate(signature, message, publicKey, secretKey);

        boolean result = DualSalt.signVerify(signature, publicKey);
        if (result){
            Log.d(TAG, "Verified signature succeeded");
        } else {
            Log.d(TAG, "Rand: " + TweetNaclFast.hexEncodeToString(rand));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Verified signature failed");
            throw new Exception();
        }
    }

    private void testSubtractPubKey(byte[] rand1, byte[] rand2) throws Exception {
        System.out.println("\nTest subtract pub key");
        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] pubKeyC = DualSalt.addPubKeys(pubKeyA, pubKeyB);
        byte[] pubKeyA2 = DualSalt.subtractPubKeys(pubKeyC, pubKeyB);
        byte[] pubKeyB2 = DualSalt.subtractPubKeys(pubKeyC, pubKeyA);
        if (Arrays.equals(pubKeyA, pubKeyA2) &&
            Arrays.equals(pubKeyB, pubKeyB2)){
            Log.d(TAG, "Success! The add and subtract did produce the same public key");
        }
        else {
            Log.d(TAG, "Random 1 key: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Random 2 key: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Fail, The add and subtract did not produce the same public key");
            throw new Exception();
        }
    }

    static void testDualSign(byte[] rand1, byte[] rand2, String testString) throws Exception {
        System.out.println("\nTest single sign");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] message = testString.getBytes();

        byte[] virtualPublicKey = DualSalt.addPubKeys(pubKeyA, pubKeyB);

        byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB);
        byte[] signature = DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);

        if (signature == null) {
            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Verified signature is null");
            throw new Exception();
        }

        boolean result = DualSalt.signVerify(signature, virtualPublicKey);
        if (result){
            Log.d(TAG, "Verified signature succeeded");
        } else {
            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Verified signature failed");
            throw new Exception();
        }
    }

    static void testSingleDecrypt(byte[] rand1, byte[] rand2, byte[] rand3, String testString) throws Exception {
        System.out.println("\nTest single decrypt");

        byte[] nonce = new byte[DualSalt.nonceLength];
        byte[] pubKey = new byte[DualSalt.publicKeyLength];
        byte[] secKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKey, secKey, rand1);
        byte[] message = testString.getBytes();

        byte[] cipherMessage = DualSalt.encrypt(message, rand2, pubKey, rand3);

        if (cipherMessage == null) {
            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Decrypt message failed");
            throw new Exception();
        }
        Log.d(TAG, "Cipher message:  " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] decryptedMessage = DualSalt.decrypt(cipherMessage, nonce, secKey);

        if (Arrays.equals(rand2, nonce) &&
            Arrays.equals(message, decryptedMessage)){
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

    static void testDualDecrypt(byte[] rand1, byte[] rand2, byte[] rand3, byte[] rand4, String testString) throws Exception {
        System.out.println("\nTest dual decrypt");

        byte[] nonce = new byte[DualSalt.nonceLength];
        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);
        byte[] pubKeyAB = DualSalt.addPubKeys(pubKeyA, pubKeyB);
        byte[] message = testString.getBytes();

        byte[] cipherMessage = DualSalt.encrypt(message, rand3, pubKeyAB, rand4);

        if (cipherMessage == null) {
            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand4));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Decrypt message failed");
            throw new Exception();
        }
        Log.d(TAG, "Cipher message: " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
        byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, nonce, secKeyB);
        if (Arrays.equals(rand3, nonce) &&
                Arrays.equals(message, decryptedMessage)){
            Log.d(TAG, "Decrypt message succeeded");
        } else {

            Log.d(TAG, "Nonce:  " + TweetNaclFast.hexEncodeToString(nonce));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Message:  " + TweetNaclFast.hexEncodeToString(message));
            if (decryptedMessage != null) {
                Log.d(TAG, "DMessage: " + TweetNaclFast.hexEncodeToString(decryptedMessage));
            }

            Log.d(TAG, "Rand 1: " + TweetNaclFast.hexEncodeToString(rand1));
            Log.d(TAG, "Rand 2: " + TweetNaclFast.hexEncodeToString(rand2));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand3));
            Log.d(TAG, "Rand 3: " + TweetNaclFast.hexEncodeToString(rand4));
            Log.d(TAG, "Test string: \"" + testString + "\"");
            Log.d(TAG, "Decrypt message failed");
            throw new Exception();
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

                testSingleSign(rand1, "The best signature in the world");
                testSingleSign(rand2, "The best signature in the all the worlds, You know like all all");
                testSingleSign(rand3, "There could be only one ultimate signature and this is it. Stop arguing");

                testSubtractPubKey(rand1, rand2);
                testSubtractPubKey(rand1, rand3);
                testSubtractPubKey(rand2, rand3);

                testDualSign(rand1, rand2, "The best signature in the world");
                testDualSign(rand1, rand3, "The best signature in the all the worlds, You know like all all");
                testDualSign(rand2, rand3, "There could be only one ultimate signature and this is it. Stop arguing");

                byte[] nonce = TweetNaclFast.hexDecode("10ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4");
                testSingleDecrypt(rand1, nonce, rand2, "The best decryption in the world");
                testSingleDecrypt(rand1, nonce, rand3, "The best decryption in the all the worlds, You know like all all");
                testSingleDecrypt(rand2, nonce, rand3, "There could be only one ultimate decryption and this is it. Stop arguing");

                testDualDecrypt(rand1, rand2, nonce, rand3, "The best decryption in the world");
                testDualDecrypt(rand3, rand1, nonce, rand2, "The best decryption in the all the worlds, You know like all all");
                testDualDecrypt(rand2, rand3, nonce, rand1, "There could be only one ultimate decryption and this is it. Stop arguing");

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
