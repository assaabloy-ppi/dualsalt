package dualsalt;

import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.Scanner;

import static org.junit.Assert.*;

public class DualSaltTestVectorTest {

    @Test
    public void testEddsaTestVector() throws Exception {
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
                assertArrayEquals("Public key do not match", dutPublicKey, publicKey);

                byte[] signature = DualSalt.signCreate(dutMessage, publicKey, secretKey);
                assertTrue("Signature do not verify correctly", DualSalt.signVerify(signature, publicKey));
                assertArrayEquals("Signature do not match", dutSignature, signature);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testSignDualTestVector() throws Exception {
        System.out.println("\nTest sing dual test vector");

        String fileName = "signDual.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeedA = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicPartA = TweetNaclFast.hexDecode(items[1]);
                byte[] dutKeySeedB = TweetNaclFast.hexDecode(items[2]);
                byte[] dutPublicPartB = TweetNaclFast.hexDecode(items[3]);
                byte[] dutVirtualPublicKey = TweetNaclFast.hexDecode(items[4]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[5]);
                byte[] dutSignature  = TweetNaclFast.hexDecode(items[6]);

                byte[] secretKeyA = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyA = new byte[DualSalt.publicKeyLength];
                byte[] secretKeyB = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyB = new byte[DualSalt.publicKeyLength];

                DualSalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                assertArrayEquals("Public key A do not match", dutPublicPartA, publicKeyA);

                DualSalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                assertArrayEquals("Public key B do not match", dutPublicPartB, publicKeyB);

                byte[] virtualPublicKey = DualSalt.addPublicKeys(publicKeyA, publicKeyB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, virtualPublicKey);

                byte[] m1 = DualSalt.signCreateDual1(dutMessage, virtualPublicKey, secretKeyA);
                byte[] m2 = DualSalt.signCreateDual2(m1, secretKeyB);
                byte[] signature = DualSalt.signCreateDual3(m1, m2, publicKeyA, secretKeyA);

                assertTrue("Signature do not verify correctly", DualSalt.signVerify(signature, virtualPublicKey));
                assertArrayEquals("Signature do not match", dutSignature, signature);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testDecryptTestVector() throws Exception {
        System.out.println("\nTest decrypt test vector");

        String fileName = "decrypt.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeed = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicKey = TweetNaclFast.hexDecode(items[1]);
                byte[] dutTempKeySeed = TweetNaclFast.hexDecode(items[2]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[3]);
                byte[] dutChipperText = TweetNaclFast.hexDecode(items[4]);

                byte[] secretKey = new byte[DualSalt.secretKeyLength];
                byte[] publicKey = new byte[DualSalt.publicKeyLength];
                DualSalt.createKeyPair(publicKey, secretKey, dutKeySeed);
                assertArrayEquals("Public key do not match", dutPublicKey, publicKey);

                byte[] chipperText = DualSalt.encrypt(dutMessage, publicKey, dutTempKeySeed);
                byte[] message = DualSalt.decrypt(chipperText, secretKey);

                assertArrayEquals("Did not encrypt correctly", chipperText, dutChipperText);

                assertArrayEquals("Did not decrypt correctly", message, dutMessage);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testDecryptDualTestVector() throws Exception {
        System.out.println("\nTest decrypt dual test vector");

        String fileName = "decryptDual.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeedA = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicPartA = TweetNaclFast.hexDecode(items[1]);
                byte[] dutKeySeedB = TweetNaclFast.hexDecode(items[2]);
                byte[] dutPublicPartB = TweetNaclFast.hexDecode(items[3]);
                byte[] dutVirtualPublicKey = TweetNaclFast.hexDecode(items[4]);
                byte[] dutTempKeySeed = TweetNaclFast.hexDecode(items[5]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[6]);
                byte[] dutChipperText = TweetNaclFast.hexDecode(items[7]);

                byte[] secretKeyA = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyA = new byte[DualSalt.publicKeyLength];
                byte[] secretKeyB = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyB = new byte[DualSalt.publicKeyLength];

                DualSalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                assertArrayEquals("Public key A do not match", dutPublicPartA, publicKeyA);

                DualSalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                assertArrayEquals("Public key B do not match", dutPublicPartB, publicKeyB);

                byte[] virtualPublicKey = DualSalt.addPublicKeys(publicKeyA, publicKeyB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, virtualPublicKey);

                byte[] chipperText = DualSalt.encrypt(dutMessage, virtualPublicKey, dutTempKeySeed);
                byte[] d1 = DualSalt.decryptDual1(chipperText, secretKeyA);
                byte[] message = DualSalt.decryptDual2(d1, chipperText, secretKeyB);

                assertArrayEquals("Did not encrypt correctly", chipperText, dutChipperText);

                assertArrayEquals("Did not decrypt correctly", message, dutMessage);
            }
        }

        System.out.println("Test succeeded");
    }

    @Test
    public void testKeyRotateTestVector() throws Exception {
        System.out.println("\nTest key rotate test vector");

        String fileName = "keyRotate.input";
        URL url = DualSaltTest.class.getResource(fileName);
        File file = new File(url.getPath());

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] items = line.split(":");
                byte[] dutKeySeedA = TweetNaclFast.hexDecode(items[0]);
                byte[] dutPublicPartA = TweetNaclFast.hexDecode(items[1]);
                byte[] dutKeySeedB = TweetNaclFast.hexDecode(items[2]);
                byte[] dutPublicPartB = TweetNaclFast.hexDecode(items[3]);
                byte[] dutVirtualPublicKey = TweetNaclFast.hexDecode(items[4]);
                byte[] dutRotateRandom = TweetNaclFast.hexDecode(items[5]);
                byte[] dutNewSecretKeyA = TweetNaclFast.hexDecode(items[6]);
                byte[] dutNewSecretKeyB  = TweetNaclFast.hexDecode(items[7]);

                byte[] secretKeyA = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyA = new byte[DualSalt.publicKeyLength];
                byte[] secretKeyB = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyB = new byte[DualSalt.publicKeyLength];

                DualSalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                assertArrayEquals("Public key A do not match", dutPublicPartA, publicKeyA);

                DualSalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                assertArrayEquals("Public key B do not match", dutPublicPartB, publicKeyB);

                byte[] virtualPublicKey = DualSalt.addPublicKeys(publicKeyA, publicKeyB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, virtualPublicKey);

                byte[] newPublicPartA = new byte[DualSalt.publicKeyLength];
                byte[] newPublicPartB = new byte[DualSalt.publicKeyLength];
                DualSalt.rotateKey(newPublicPartA, secretKeyA, dutRotateRandom, true);
                DualSalt.rotateKey(newPublicPartB, secretKeyB, dutRotateRandom, false);

                byte[] newVirtualPublicKey = DualSalt.addPublicKeys(newPublicPartA, newPublicPartB);
                assertArrayEquals("Virtual public key do not match", dutVirtualPublicKey, newVirtualPublicKey);

                assertArrayEquals("Secret Key A was not updated correctly", secretKeyA, dutNewSecretKeyA);
                assertArrayEquals("Secret Key B was not updated correctly", secretKeyB, dutNewSecretKeyB);
            }
        }

        System.out.println("Test succeeded");
    }
}