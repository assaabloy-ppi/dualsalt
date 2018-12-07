package dualsalt;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;

import static org.junit.Assert.*;

public class DualSaltTest {

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    private byte[] addArrays(byte[] a, byte[] b){
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

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

    private static byte[] calculatePublicKey(byte[] scalar) {
        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        long[][] p = new long[4][];
        p[0] = new long[16];
        p[1] = new long[16];
        p[2] = new long[16];
        p[3] = new long[16];
        TweetNaclFast.scalarbase(p, scalar, 0);
        TweetNaclFast.pack(publicKey, p);
        return publicKey;
    }

    static byte[] addGroupElements(byte[] elementA, byte[] elementB) {
        long[][] a = unpack(elementA);
        long[][] b = unpack(elementB);

        TweetNaclFast.add(a, b);

        byte[] elementAB = new byte[TweetNaclFast.ScalarMult.groupElementLength];
        TweetNaclFast.pack(elementAB, a);

        return elementAB;
    }

    private static long[][] unpack(byte[] packedGroupEl) {
        long[][] unpackedGroupEl = new long[4][];
        unpackedGroupEl[0] = new long[16];
        unpackedGroupEl[1] = new long[16];
        unpackedGroupEl[2] = new long[16];
        unpackedGroupEl[3] = new long[16];
        
        int result = TweetNaclFast.unpackneg(unpackedGroupEl, packedGroupEl);
        if (result != 0)
            throw new IllegalArgumentException("Group element can not be unpacked");

        // Change sign from neg to pos
        TweetNaclFast.Z(unpackedGroupEl[0], TweetNaclFast.gf0, unpackedGroupEl[0]);
        TweetNaclFast.M(unpackedGroupEl[3], unpackedGroupEl[0], unpackedGroupEl[1]);

        return unpackedGroupEl;
    }

    private void testKeyAddition(byte[] keySeedA, byte[] keySeedB){
        System.out.println("\nTest key addition");

        byte[] pubKeyA = new byte[DualSalt.dualPublicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.dualPublicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createDualKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createDualKeyPair(pubKeyB, secKeyB, keySeedB);

        byte[] pubKeyAB1 = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

        byte[] secScalarAB = addScalars(secKeyA, secKeyB);
        byte[] secSecAB = new byte[DualSalt.secretKeyLength];
        System.arraycopy(secScalarAB, 0, secSecAB, 0, TweetNaclFast.ScalarMult.scalarLength);
        byte[] pubKeyAB2 = calculatePublicKey(secSecAB);

        System.out.println( "Group public key 1: " + TweetNaclFast.hexEncodeToString(pubKeyAB1));
        System.out.println( "Group public key 2: " + TweetNaclFast.hexEncodeToString(pubKeyAB2));

        assertArrayEquals("Group public key not ok", pubKeyAB1, pubKeyAB2);
    }

    private static void testRotateKeys(byte[] keySeedA, byte[] keySeedB, byte[] rotateSeed) {
        System.out.println("\nTest rotate keys");

        byte[] pubKeyA1 = new byte[DualSalt.dualPublicKeyLength];
        byte[] pubKeyB1 = new byte[DualSalt.dualPublicKeyLength];
        byte[] secKeyA1 = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB1 = new byte[DualSalt.secretKeyLength];
        DualSalt.createDualKeyPair(pubKeyA1, secKeyA1, keySeedA);
        DualSalt.createDualKeyPair(pubKeyB1, secKeyB1, keySeedB);

        byte[] pubKeyAB1 = DualSalt.addPublicKeyParts(pubKeyA1, pubKeyB1);

        byte[] secKeyA2 = DualSalt.rotateKey(secKeyA1, rotateSeed, true);
        byte[] secKeyB2 = DualSalt.rotateKey(secKeyB1, rotateSeed, false);
        byte[] pubKeyA2 = Arrays.copyOfRange(secKeyA2, 32, DualSalt.secretKeyLength);
        byte[] pubKeyB2 = Arrays.copyOfRange(secKeyB2, 32, DualSalt.secretKeyLength);

        assertArrayNotEquals("Fail, A1 and B1 was the same", pubKeyA1, pubKeyB1);
        assertArrayNotEquals("Fail, A1 and A2 was the same", pubKeyA1, pubKeyA2);
        assertArrayNotEquals("Fail, A1 and B2 was the same", pubKeyA1, pubKeyB2);
        assertArrayNotEquals("Fail, B1 and A2 was the same", pubKeyB1, pubKeyA2);
        assertArrayNotEquals("Fail, B1 and B2 was the same", pubKeyB1, pubKeyB2);
        assertArrayNotEquals("Fail, A2 and B2 was the same", pubKeyA2, pubKeyB2);

        byte[] pubKeyAB2 = addGroupElements(pubKeyA2, pubKeyB2);

        assertArrayEquals("Fail, The rotated virtual key did not produce the same pub key", pubKeyAB1, pubKeyAB2);
    }

    private void testSingleSign(byte[] keySeed, byte[] message){
        System.out.println("\nTest single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createSingleKeyPair(publicKey, secretKey, keySeed);

        byte[] signature = DualSalt.signCreate(message, secretKey);

        assertTrue("Verified signature failed", DualSalt.signVerify(signature, publicKey));
    }

    private void testNegativeSingleSign(byte[] keySeed, byte[] message) {
        System.out.println("\nTest negative single sign");

        byte[] publicKey = new byte[DualSalt.publicKeyLength];
        byte[] secretKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createSingleKeyPair(publicKey, secretKey, keySeed);

        byte[] signature = DualSalt.signCreate(message, secretKey);

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

    private void testDualSign(byte[] keySeedA, byte[] keySeedB, byte[] random, byte[] message) {
        System.out.println("\nTest dual sign");

        byte[] hash = new byte[64];
        TweetNaclFast.crypto_hash(hash, random, 0, random.length);
        byte[] randomA = Arrays.copyOfRange(hash, 0, 32);
        byte[] randomB = Arrays.copyOfRange(hash, 32, hash.length);

        byte[] pubKeyA = new byte[DualSalt.dualPublicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.dualPublicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createDualKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createDualKeyPair(pubKeyB, secKeyB, keySeedB);

        byte[] virtualPublicKey = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

        byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, randomA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB, randomB);
        byte[] signature = DualSalt.signCreateDual3(m1, m2, secKeyA, randomA);

        assertTrue("Verified signature failed", DualSalt.signVerify(signature, virtualPublicKey));
    }

    private void testNegativeDualSign(byte[] keySeedA, byte[] keySeedB, byte[] random,  byte[] message) {
        System.out.println("\nTest negative dual sign");

        byte[] hash = new byte[64];
        TweetNaclFast.crypto_hash(hash, random, 0, random.length);
        byte[] randomA = Arrays.copyOfRange(hash, 0, 32);
        byte[] randomB = Arrays.copyOfRange(hash, 32, hash.length);

        byte[] pubKeyA = new byte[DualSalt.dualPublicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.dualPublicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createDualKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createDualKeyPair(pubKeyB, secKeyB, keySeedB);

        byte[] virtualPublicKey = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

        byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, randomA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB, randomB);

        int steps = 10;
        for (int i = 0; i <= steps; i++) {
            int j = ((m2.length - 1) * i) / steps;
            byte[] tempM2 = m2.clone();
            tempM2[j] = (byte) (tempM2[j] ^ 0x1);
            try {
                DualSalt.signCreateDual3(m1, tempM2, secKeyA, randomA);
                fail("Validated succeeded but it should not");
            } catch (IllegalArgumentException iae) {
                // Do nothing. It shall fail.
            }
        }

        for (int i = 0; i <= steps; i++) {
            int j = ((32 - 1) * i) / steps;
            byte[] tempSecKeyA = secKeyA.clone();
            tempSecKeyA[32+j] = (byte) (tempSecKeyA[32+j] ^ 0x1);
            try {
                DualSalt.signCreateDual3(m1, m2, tempSecKeyA, randomA);
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
        DualSalt.createSingleKeyPair(pubKey, secKey, keySeed);

        byte[] cipherMessage = DualSalt.encrypt(message, pubKey, keySeedE);
        System.out.println( "Cipher message:  " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] decryptedMessage = DualSalt.decrypt(cipherMessage, secKey);

        assertArrayEquals("Decrypt message failed", message, decryptedMessage);
    }

    private void testNegativeSingleDecrypt(byte[] keySeed, byte[] keySeedE, byte[] message) {
        System.out.println("\nTest negative single decrypt");

        byte[] pubKey = new byte[DualSalt.publicKeyLength];
        byte[] secKey = new byte[DualSalt.secretKeyLength];
        DualSalt.createSingleKeyPair(pubKey, secKey, keySeed);

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

        byte[] pubKeyA = new byte[DualSalt.dualPublicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.dualPublicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createDualKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createDualKeyPair(pubKeyB, secKeyB, keySeedB);
        byte[] pubKeyAB = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

        byte[] cipherMessage = DualSalt.encrypt(message, pubKeyAB, keySeedE);
        System.out.println( "Cipher message: " + TweetNaclFast.hexEncodeToString(cipherMessage));

        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyA);
        byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, secKeyB);
        assertArrayEquals("Decrypt message failed", message, decryptedMessage);
    }

    private void testNegativeDualDecrypt(byte[] keySeedA, byte[] keySeedB, byte[] keySeedE, byte[] message) {
        System.out.println("\nTest negative dual decrypt");

        byte[] pubKeyA = new byte[DualSalt.dualPublicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.dualPublicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createDualKeyPair(pubKeyA, secKeyA, keySeedA);
        DualSalt.createDualKeyPair(pubKeyB, secKeyB, keySeedB);
        byte[] pubKeyAB = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

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

    public void testBadGroupElement(byte[] badGroupElement) {
        exceptionRule.expect(IllegalArgumentException.class);
        exceptionRule.expectMessage("Element not in group");
        final byte[] dummySecretKey = TweetNaclFast.hexDecode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        DualSalt.decryptDual1(addArrays(badGroupElement, new byte[]{0}), dummySecretKey);
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
    public void testDualSign1() { testDualSign(rand1, rand2, rand3, testMessage1); }

    @Test
    public void testDualSign2() {
            testDualSign(rand1, rand3, rand2, testMessage2);
    }

    @Test
    public void testDualSign3() {
            testDualSign(rand2, rand3, rand1, testMessage3);
    }

    @Test
    public void testSingleDecrypt1() { testSingleDecrypt(rand1, rand2, testMessage1); }

    @Test
    public void testSingleDecrypt2() {
            testSingleDecrypt(rand1, rand3, testMessage2);
    }

    @Test
    public void testSingleDecrypt3() {
            testSingleDecrypt(rand2, rand3, testMessage3);
    }

    @Test
    public void testDualDecrypt1() { testDualDecrypt(rand1, rand2, rand3, testMessage1); }

    @Test
    public void testDualDecrypt2() {
            testDualDecrypt(rand3, rand1, rand2, testMessage2);
    }

    @Test
    public void testDualDecrypt3() {
            testDualDecrypt(rand2, rand3, rand1, testMessage3);
    }

    @Test
    public void testNegativeSingleSign1() { testNegativeSingleSign(rand1, testMessage1); }

    @Test
    public void testNegativeSingleSign2() {
            testNegativeSingleSign(rand2, testMessage2);
    }

    @Test
    public void testNegativeSingleSign3() {
            testNegativeSingleSign(rand3, testMessage3);
    }

    @Test
    public void testNegativeDualSign1() { testNegativeDualSign(rand1, rand2, rand3, testMessage1); }

    @Test
    public void testNegativeDualSign2() {
            testNegativeDualSign(rand1, rand3, rand2, testMessage2);
    }

    @Test
    public void testNegativeDualSign3() {
            testNegativeDualSign(rand2, rand3, rand1, testMessage3);
    }

    @Test
    public void testNegativeSingleDecrypt1() { testNegativeSingleDecrypt(rand1, rand2, testMessage1); }

    @Test
    public void testNegativeSingleDecrypt2() {
            testNegativeSingleDecrypt(rand1, rand3, testMessage2);
    }

    @Test
    public void testNegativeSingleDecrypt3() {
            testNegativeSingleDecrypt(rand2, rand3, testMessage3);
    }

    @Test
    public void testNegativeDualDecrypt1() { testNegativeDualDecrypt(rand1, rand2, rand3, testMessage1); }

    @Test
    public void testNegativeDualDecrypt2() {
            testNegativeDualDecrypt(rand3, rand1, rand2, testMessage2);
    }

    @Test
    public void testNegativeDualDecrypt3() { testNegativeDualDecrypt(rand2, rand3, rand1, testMessage3); }


    @Test
    public void testBadGroupElement1() {
        // 0 (order 4)
        testBadGroupElement(TweetNaclFast.hexDecode("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    @Test
    public void testBadGroupElement2() {
        // 1 (order 1)
        testBadGroupElement(TweetNaclFast.hexDecode("0100000000000000000000000000000000000000000000000000000000000000"));
    }

    @Test
    public void testBadGroupElement3() {
        // 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8)
        testBadGroupElement(TweetNaclFast.hexDecode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"));
    }

    @Test
    public void testBadGroupElement4() {
        // 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
        testBadGroupElement(TweetNaclFast.hexDecode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"));
    }

    @Test
    public void testBadGroupElement5() {
        // p-1 (order 2)
        testBadGroupElement(TweetNaclFast.hexDecode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    }

    @Test
    public void testBadGroupElement6() {
        // p (=0, order 4)
        testBadGroupElement(TweetNaclFast.hexDecode("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    }

    @Test
    public void testBadGroupElement7() {
        // p+1 (=1, order 1)
        testBadGroupElement(TweetNaclFast.hexDecode("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    }
}
