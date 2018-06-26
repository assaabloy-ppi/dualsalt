package dualsalt.tests;

import dualsalt.DualSalt;
import dualsalt.TweetNaclFast;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.Scanner;

public class DualSaltTestVectorTest {

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

        System.out.println("Test succeeded");
    }

    private static void testSignDualTestVector() throws Exception {
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
                if (!Arrays.equals(dutPublicPartA, publicKeyA)) {
                    throw new Exception("Public key A do not match");
                }

                DualSalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                if (!Arrays.equals(dutPublicPartB, publicKeyB)) {
                    throw new Exception("Public key B do not match");
                }

                byte[] virtualPublicKey = DualSalt.addPublicKeys(publicKeyA, publicKeyB);
                if (!Arrays.equals(dutVirtualPublicKey, virtualPublicKey)) {
                    throw new Exception("Virtual public key do not match");
                }

                byte[] m1 = DualSalt.signCreateDual1(dutMessage, virtualPublicKey, secretKeyA);
                byte[] m2 = DualSalt.signCreateDual2(m1, secretKeyB);
                byte[] signature = DualSalt.signCreateDual3(m1, m2, publicKeyA, secretKeyA);

                if (!DualSalt.signVerify(signature, virtualPublicKey)) {
                    throw new Exception("Signature do not verify correctly");
                }

                if (!Arrays.equals(signature, dutSignature)) {
                    throw new Exception("Signature do not match test signature");
                }
            }
        }

        System.out.println("Test succeeded");
    }

    private static void testDecryptTestVector() throws Exception {
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
                byte[] dutNonce = TweetNaclFast.hexDecode(items[3]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[4]);
                byte[] dutChipperText = TweetNaclFast.hexDecode(items[5]);

                byte[] secretKey = new byte[DualSalt.secretKeyLength];
                byte[] publicKey = new byte[DualSalt.publicKeyLength];
                DualSalt.createKeyPair(publicKey, secretKey, dutKeySeed);
                if (!Arrays.equals(dutPublicKey, publicKey)) {
                    throw new Exception("Public key do not match");
                }

                byte[] nonce = new byte[DualSalt.nonceLength];
                byte[] chipperText = DualSalt.encrypt(dutMessage, dutNonce, publicKey, dutTempKeySeed);
                byte[] message = DualSalt.decrypt(chipperText, nonce, secretKey);

                if (!Arrays.equals(chipperText, dutChipperText)) {
                    throw new Exception("Did not encrypt correctly");
                }

                if (!Arrays.equals(message, dutMessage)) {
                    throw new Exception("Did not decrypt correctly");
                }

                if (!Arrays.equals(nonce, dutNonce)) {
                    throw new Exception("Nonce do not match");
                }
            }
        }

        System.out.println("Test succeeded");
    }

    private static void testDecryptDualTestVector() throws Exception {
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
                byte[] dutNonce = TweetNaclFast.hexDecode(items[6]);
                byte[] dutMessage = TweetNaclFast.hexDecode(items[7]);
                byte[] dutChipperText = TweetNaclFast.hexDecode(items[8]);

                byte[] secretKeyA = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyA = new byte[DualSalt.publicKeyLength];
                byte[] secretKeyB = new byte[DualSalt.secretKeyLength];
                byte[] publicKeyB = new byte[DualSalt.publicKeyLength];

                DualSalt.createKeyPair(publicKeyA, secretKeyA, dutKeySeedA);
                if (!Arrays.equals(dutPublicPartA, publicKeyA)) {
                    throw new Exception("Public key A do not match");
                }

                DualSalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                if (!Arrays.equals(dutPublicPartB, publicKeyB)) {
                    throw new Exception("Public key B do not match");
                }

                byte[] virtualPublicKey = DualSalt.addPublicKeys(publicKeyA, publicKeyB);
                if (!Arrays.equals(dutVirtualPublicKey, virtualPublicKey)) {
                    throw new Exception("Virtual public key do not match");
                }

                byte[] nonce = new byte[DualSalt.nonceLength];
                byte[] chipperText = DualSalt.encrypt(dutMessage, dutNonce, virtualPublicKey, dutTempKeySeed);
                byte[] d1 = DualSalt.decryptDual1(chipperText, secretKeyA);
                byte[] message = DualSalt.decryptDual2(d1, chipperText, nonce, secretKeyB);

                if (!Arrays.equals(chipperText, dutChipperText)) {
                    throw new Exception("Did not encrypt correctly");
                }

                if (!Arrays.equals(message, dutMessage)) {
                    throw new Exception("Did not decrypt correctly");
                }

                if (!Arrays.equals(nonce, dutNonce)) {
                    throw new Exception("Nonce do not match");
                }
            }
        }

        System.out.println("Test succeeded");
    }

    private static void testKeyRotateTestVector() throws Exception {
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
                if (!Arrays.equals(dutPublicPartA, publicKeyA)) {
                    throw new Exception("Public key A do not match");
                }

                DualSalt.createKeyPair(publicKeyB, secretKeyB, dutKeySeedB);
                if (!Arrays.equals(dutPublicPartB, publicKeyB)) {
                    throw new Exception("Public key B do not match");
                }

                byte[] virtualPublicKey = DualSalt.addPublicKeys(publicKeyA, publicKeyB);
                if (!Arrays.equals(dutVirtualPublicKey, virtualPublicKey)) {
                    throw new Exception("Virtual public key do not match");
                }

                byte[] newPublicPartA = new byte[DualSalt.publicKeyLength];
                byte[] newPublicPartB = new byte[DualSalt.publicKeyLength];
                DualSalt.rotateKey(newPublicPartA, secretKeyA, dutRotateRandom, true);
                DualSalt.rotateKey(newPublicPartB, secretKeyB, dutRotateRandom, false);

                byte[] newVirtualPublicKey = DualSalt.addPublicKeys(newPublicPartA, newPublicPartB);
                if (!Arrays.equals(dutVirtualPublicKey, newVirtualPublicKey)) {
                    throw new Exception("Virtual public key do not match");
                }

                if (!Arrays.equals(secretKeyA, dutNewSecretKeyA)) {
                    throw new Exception("Secret Key A was not updated correctly");
                }

                if (!Arrays.equals(secretKeyB, dutNewSecretKeyB)) {
                    throw new Exception("Secret Key B was not updated correctly");
                }
            }
        }

        System.out.println("Test succeeded");
    }

    private void run() {
        try {
            testEddsaTestVector();
            testSignDualTestVector();
            testDecryptTestVector();
            testDecryptDualTestVector();
            testKeyRotateTestVector();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        System.out.println("\nSUCCESS! All tests were successful.");
    }

    public static void main(String[] args) {
        DualSaltTestVectorTest t = new DualSaltTestVectorTest();
        t.run();
    }
}