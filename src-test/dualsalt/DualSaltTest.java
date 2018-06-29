package dualsalt;


import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class DualSaltTest {

    private static void assertArrayNotEquals(String message, byte[] expecteds, byte[] actuals) {
        try {
            assertArrayEquals(expecteds, actuals);
        } catch (AssertionError e) {
            return;
        }
        fail(message);
    }

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

    private void testKeyAddition(byte[] keySeedA, byte[] keySeedB) {
        System.out.println("\nTest key addition");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);

        byte[] pubKeyAB1 = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] secScalarAB = addScalars(secKeyA, secKeyB);
        byte[] secSecAB = new byte[DualSalt.secretKeyLength];
        System.arraycopy(secScalarAB, 0, secSecAB, 0, TweetNaclFast.ScalarMult.scalarLength);
        byte[] pubKeyAB2 = DualSalt.calculatePublicKey(secSecAB);

        System.out.println( "Group public key 1: " + TweetNaclFast.hexEncodeToString(pubKeyAB1));
        System.out.println( "Group public key 2: " + TweetNaclFast.hexEncodeToString(pubKeyAB2));

        assertArrayEquals("Group public key not ok", pubKeyAB1, pubKeyAB2);
    }

    private static void testRotateKeys(byte[] keySeedA, byte[] keySeedB, byte[] rotateSeed) {
        System.out.println("\nTest rotate keys");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);
        byte[] oldSecRandA = Arrays.copyOfRange(secKeyA, 32, DualSalt.secretKeyLength);
        byte[] oldSecRandB = Arrays.copyOfRange(secKeyB, 32, DualSalt.secretKeyLength);

        byte[] pubKeyAB1 = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] pubKeyA2 = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB2 = new byte[DualSalt.publicKeyLength];
        DualSalt.rotateKey(pubKeyA2, secKeyA, rotateSeed, true);
        DualSalt.rotateKey(pubKeyB2, secKeyB, rotateSeed, false);

        assertArrayNotEquals("Fail, Some pub keys was the same", pubKeyA, pubKeyB);
        assertArrayNotEquals("Fail, Some pub keys was the same", pubKeyA, pubKeyA2);
        assertArrayNotEquals("Fail, Some pub keys was the same", pubKeyA, pubKeyB2);
        assertArrayNotEquals("Fail, Some pub keys was the same", pubKeyB, pubKeyA2);
        assertArrayNotEquals("Fail, Some pub keys was the same", pubKeyB, pubKeyB2);
        assertArrayNotEquals("Fail, Some pub keys was the same", pubKeyA2, pubKeyB2);

        byte[] newSecRandA = Arrays.copyOfRange(secKeyA, 32, DualSalt.secretKeyLength);
        byte[] newSecRandB = Arrays.copyOfRange(secKeyB, 32, DualSalt.secretKeyLength);
        assertArrayNotEquals("Fail, The secret random part has not changed correctly", oldSecRandA, newSecRandA);
        assertArrayNotEquals("Fail, The secret random part has not changed correctly", oldSecRandB, newSecRandB);
        assertArrayNotEquals("Fail, The secret random part has not changed correctly", newSecRandA, newSecRandB);

        byte[] pubKeyAB2 = DualSalt.addPublicKeys(pubKeyA2, pubKeyB2);

        assertArrayEquals("Fail, The rotated virtual key did not produce the same pub key", pubKeyAB1, pubKeyAB2);
    }

    private void testSingleSign(byte[] keySeed, byte[] message){
        System.out.println("\nTest single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(publicKey, secretKey, keySeed);

        byte[] signature = DualSalt.signCreate(message, publicKey, secretKey);

        assertTrue("Verified signature failed", DualSalt.signVerify(signature, publicKey));
    }

    private void testNegativeSingleSign(byte[] keySeed, byte[] message) {
        System.out.println("\nTest negative single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(publicKey, secretKey, keySeed);

        byte[] signature = DualSalt.signCreate(message, publicKey, secretKey);

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((signature.length - 1) * i) / steps;
            byte[] tempSignature = signature.clone();
            tempSignature[j] = (byte) (tempSignature[j] ^ 0x1);
            assertFalse("Validated succeeded but it should not", DualSalt.signVerify(tempSignature, publicKey));
        }

        for (int i = 0; i <= steps; i++) {
            int j = ((publicKey.length - 1) * i) / steps;
            byte[] tempPublicKey = publicKey.clone();
            tempPublicKey[j] = (byte) (tempPublicKey[j] ^ 0x1);
            assertFalse("Validated succeeded but it should not", DualSalt.signVerify(signature, tempPublicKey));
        }

        System.out.println( "Signature validation fail when it shall");
    }

    private void testSubtractPubKey(byte[] keySeedA, byte[] keySeedB) {
        System.out.println("\nTest subtract pub key");
        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);
        byte[] pubKeyC = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
        byte[] pubKeyA2 = DualSalt.subtractPublicKeys(pubKeyC, pubKeyB);
        byte[] pubKeyB2 = DualSalt.subtractPublicKeys(pubKeyC, pubKeyA);
        assertArrayEquals("Fail, The add and subtract did not produce the same public key", pubKeyA, pubKeyA2);
        assertArrayEquals("Fail, The add and subtract did not produce the same public key", pubKeyB, pubKeyB2);
    }

    private void testDualSign(byte[] keySeedA, byte[] keySeedB, byte[] message) {
        System.out.println("\nTest dual sign");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);

        byte[] virtualPublicKey = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB);
        byte[] signature = DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);

        assertTrue("Verified signature failed", DualSalt.signVerify(signature, virtualPublicKey));
    }

    private void testNegativeDualSign(byte[] keySeedA, byte[] keySeedB, byte[] message) {
        System.out.println("\nTest negative dual sign");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);

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
                fail("Validated succeeded but it should not");
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
                fail("Validated succeeded but it should not");
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        System.out.println( "Signature validation fail when it shall");
    }

    private void testSingleDecrypt(byte[] keySeed, byte[] keySeedE, byte[] message){
        System.out.println("\nTest single decrypt");

        byte[] pubKey = new byte[DualSalt.publicKeyLength];
        byte[] secKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKey, secKey, keySeed);

        byte[] cipherMessage = DualSalt.encrypt(message, pubKey, keySeedE);
        System.out.println( "Cipher message:  " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] decryptedMessage = DualSalt.decrypt(cipherMessage, secKey);

        assertArrayEquals("Decrypt message failed", message, decryptedMessage);
    }

    private void testNegativeSingleDecrypt(byte[] keySeed, byte[] keySeedE, byte[] message) {
        System.out.println("\nTest negative single decrypt");

        byte[] pubKey = new byte[DualSalt.publicKeyLength];
        byte[] secKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKey, secKey, keySeed);

        byte[] cipherMessage = DualSalt.encrypt(message, pubKey, keySeedE);
        System.out.println( "Cipher message:  " + TweetNaclFast.hexEncodeToString(cipherMessage));

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((cipherMessage.length - 1) * i) / steps;
            byte[] tempCipherMessage = cipherMessage.clone();
            tempCipherMessage[j] = (byte) (tempCipherMessage[j] ^ 0x1);
            try {
                DualSalt.decrypt(tempCipherMessage, secKey);
                fail("Decryption succeeded but it should not");
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        System.out.println( "Message decryption validation fail when it shall");
    }

    private void testDualDecrypt(byte[] keySeedA, byte[] keySeedB, byte[] keySeedE, byte[] message) {
        System.out.println("\nTest dual decrypt");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);
        byte[] pubKeyAB = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] cipherMessage = DualSalt.encrypt(message, pubKeyAB, keySeedE);
        System.out.println( "Cipher message: " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
        byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, secKeyB);
        assertArrayEquals("Decrypt message failed", message, decryptedMessage);
    }

    private void testNegativeDualDecrypt(byte[] keySeedA, byte[] keySeedB, byte[] keySeedE, byte[] message) {
        System.out.println("\nTest negative dual decrypt");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createKeyPair(pubKeyB, secKeyB, keySeedB);
        byte[] pubKeyAB = DualSalt.addPublicKeys(pubKeyA, pubKeyB);

        byte[] cipherMessage = DualSalt.encrypt(message, pubKeyAB, keySeedE);
        System.out.println( "Cipher message: " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((cipherMessage.length - 1) * i) / steps;
            byte[] tempCipherMessage = cipherMessage.clone();
            tempCipherMessage[j] = (byte) (tempCipherMessage[j] ^ 0x1);
            try {
                DualSalt.decryptDual2(d1, tempCipherMessage, secKeyB);
                fail("Decryption succeeded but it should not");
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        for (int i = 0; i <= steps; i++) {
            int j = ((d1.length - 1) * i) / steps;
            byte[] tempD1 = d1.clone();
            tempD1[j] = (byte) (tempD1[j] ^ 0x1);
            try {
                DualSalt.decryptDual2(tempD1, cipherMessage, secKeyB);
                fail("Decryption succeeded but it should not");
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        System.out.println( "Message decryption validation fail when it shall");
    }


    private byte[] rand1 = TweetNaclFast
            .hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
    private byte[] rand2 = TweetNaclFast
            .hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
    private byte[] rand3 = TweetNaclFast
            .hexDecode("995afd8c14adb49410ecd957aecc8d02e56f0eef73ade8f79bc1d16a99cbc5e4");
    private byte[] testMessage1 = "The best signature in the world".getBytes();
    private byte[] testMessage2 = "The best signature in the all the worlds, You know like all all".getBytes();
    private byte[] testMessage3 = "There could be only one ultimate signature and this is it. Stop arguing".getBytes();

    @Test
    public void testKeyAddition1() {
        testKeyAddition(rand1, rand2);
    }

    @Test
    public void testKeyAddition2() {
        testKeyAddition(rand1, rand3);
    }

    @Test
    public void testKeyAddition3() {
        testKeyAddition(rand2, rand3);
    }

    @Test
    public void testRotateKeys1() {
        testRotateKeys(rand1, rand2, rand3);
    }

    @Test
    public void testRotateKeys2() {
        testRotateKeys(rand1, rand3, rand2);
    }

    @Test
    public void testRotateKeys3() {
        testRotateKeys(rand2, rand3, rand1);
    }

    @Test
    public void testSingleSign1() {
        testSingleSign(rand1, testMessage1);
    }

    @Test
    public void testSingleSign2() {
        testSingleSign(rand2, testMessage2);
    }

    @Test
    public void testSingleSign3() {
        testSingleSign(rand3, testMessage3);
    }

    @Test
    public void testSubtractPubKey1() {
            testSubtractPubKey(rand1, rand2);
    }

    @Test
    public void testSubtractPubKey2() {
            testSubtractPubKey(rand1, rand3);
    }

    @Test
    public void testSubtractPubKey3() {
            testSubtractPubKey(rand2, rand3);
    }

    @Test
    public void testDualSign1() {

            testDualSign(rand1, rand2, testMessage1);
    }

    @Test
    public void testDualSign2() {
            testDualSign(rand1, rand3, testMessage2);
    }

    @Test
    public void testDualSign3() {
            testDualSign(rand2, rand3, testMessage3);
    }

    @Test
    public void testSingleDecrypt1() {

            testSingleDecrypt(rand1, rand2, testMessage1);
    }

    @Test
    public void testSingleDecrypt2() {
            testSingleDecrypt(rand1, rand3, testMessage2);
    }

    @Test
    public void testSingleDecrypt3() {
            testSingleDecrypt(rand2, rand3, testMessage3);
    }

    @Test
    public void testDualDecrypt1() {

            testDualDecrypt(rand1, rand2, rand3, testMessage1);
    }

    @Test
    public void testDualDecrypt2() {
            testDualDecrypt(rand3, rand1, rand2, testMessage2);
    }

    @Test
    public void testDualDecrypt3() {
            testDualDecrypt(rand2, rand3, rand1, testMessage3);
    }

    @Test
    public void testNegativeSingleSign1() {

            testNegativeSingleSign(rand1, testMessage1);
    }

    @Test
    public void testNegativeSingleSign2() {
            testNegativeSingleSign(rand2, testMessage2);
    }

    @Test
    public void testNegativeSingleSign3() {
            testNegativeSingleSign(rand3, testMessage3);
    }

    @Test
    public void testNegativeDualSign1() {

            testNegativeDualSign(rand1, rand2, testMessage1);
    }

    @Test
    public void testNegativeDualSign2() {
            testNegativeDualSign(rand1, rand3, testMessage2);
    }

    @Test
    public void testNegativeDualSign3() {
            testNegativeDualSign(rand2, rand3, testMessage3);
    }

    @Test
    public void testNegativeSingleDecrypt1() {

            testNegativeSingleDecrypt(rand1, rand2, testMessage1);
    }

    @Test
    public void testNegativeSingleDecrypt2() {
            testNegativeSingleDecrypt(rand1, rand3, testMessage2);
    }

    @Test
    public void testNegativeSingleDecrypt3() {
            testNegativeSingleDecrypt(rand2, rand3, testMessage3);
    }

    @Test
    public void testNegativeDualDecrypt1() {

            testNegativeDualDecrypt(rand1, rand2, rand3, testMessage1);
    }

    @Test
    public void testNegativeDualDecrypt2() {
            testNegativeDualDecrypt(rand3, rand1, rand2, testMessage2);
    }

    @Test
    public void testNegativeDualDecrypt3() {
            testNegativeDualDecrypt(rand2, rand3, rand1, testMessage3);
    }
}
