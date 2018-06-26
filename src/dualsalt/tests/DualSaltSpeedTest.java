package dualsalt.tests;

import dualsalt.DualSalt;
import dualsalt.TweetNaclFast;

public class DualSaltSpeedTest {

    private static final String TAG = "DualSaltSpeedTest";

    private void testSignSpeed() {
        System.out.println("\nTest sign speed");

        byte[] rand1 = TweetNaclFast.hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
        byte[] rand2 = TweetNaclFast.hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);

        byte[] virtualPublicKey = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
        String testString = "Fy fabian vad jag vill ha en ny dator";
        byte[] message = testString.getBytes();
        byte[] signature = DualSalt.signCreate(message, pubKeyA, secKeyA);

        byte[] tweetSecretKeyA = new byte[64];
        System.arraycopy(rand1, 0, tweetSecretKeyA, 0 , DualSalt.seedLength);
        System.arraycopy(pubKeyA, 0, tweetSecretKeyA, DualSalt.seedLength, DualSalt.publicKeyLength);
        byte[] sm = new byte[message.length + 64];
        byte[] tmp = new byte[sm.length];
        int iterations = 1000;

        long totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            TweetNaclFast.crypto_sign(sm, -1, message, 0, message.length, tweetSecretKeyA);
            totalTime += System.nanoTime() - startTime;
        }
        long signRef = totalTime/(iterations*1000);
        Log.d(TAG, "TweetNaclFast.crypto_sign execution time: " + signRef + "µs");

        totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            DualSalt.signCreate(message, pubKeyA, secKeyA);
            totalTime += System.nanoTime() - startTime;
        }
        long signSingle = totalTime/(iterations*1000);
        Log.d(TAG, "DualSalt.signCreate execution time: " + signSingle + "µs " + signSingle*100/signRef + "%");

        totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            byte[] m1 = DualSalt.signCreateDual1(message, virtualPublicKey, secKeyA);
            byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB);
            DualSalt.signCreateDual3(m1, m2, pubKeyA, secKeyA);
            totalTime += System.nanoTime() - startTime;
        }
        long signDual = totalTime/(iterations*1000);
        Log.d(TAG, "DualSalt.signCreateDual execution time: " + signDual + "µs " + signDual*100/signRef + "%");

        totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            TweetNaclFast.crypto_sign_open(tmp, 0, signature, 0, signature.length, pubKeyA);
            totalTime += System.nanoTime() - startTime;
        }
        long verifyRef = totalTime/(iterations*1000);
        Log.d(TAG, "TweetNaclFast.crypto_sign_open execution time: " + verifyRef + "µs");

        totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            DualSalt.signVerify(signature, pubKeyA);
            totalTime += System.nanoTime() - startTime;
        }
        long verify = totalTime/(iterations*1000);
        Log.d(TAG, "DualSalt.signVerify execution time: " + verify + "µs " + verify*100/verifyRef + "%");
    }

    private void testDecryptSpeed() {
        System.out.println("\nTest decrypt speed");

        byte[] rand1 = TweetNaclFast.hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
        byte[] rand2 = TweetNaclFast.hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
        byte[] rand3 = TweetNaclFast.hexDecode("E14A55160C418542BFB0B4DCEB4CAA489A09AF8B9F61104F27E621BCB5002388");
        byte[] nonce = TweetNaclFast.hexDecode("775AC10266C022122581BFFC502F30415B05826E17BF3BE9");

        byte[] pubKeyA = new byte[DualSalt.publicKeyLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPair(pubKeyB, secKeyB, rand2);

        byte[] virtualPublicKey = DualSalt.addPublicKeys(pubKeyA, pubKeyB);
        String testString = "Fy fabian vad jag vill ha en ny dator";
        byte[] message = testString.getBytes();
        byte[] nonceOut = new byte[DualSalt.nonceLength];
        byte[] chipperTextSingle = DualSalt.encrypt(message, nonce, pubKeyA, rand3);
        byte[] chipperTextDual = DualSalt.encrypt(message, nonce, virtualPublicKey, rand3);
        int iterations = 1000;

        long totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            DualSalt.encrypt(message, nonce, pubKeyA, rand3);
            totalTime += System.nanoTime() - startTime;
        }
        long encrypt = totalTime/(iterations*1000);
        Log.d(TAG, "DualSalt.encrypt execution time: " + encrypt + "µs");

        totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            DualSalt.decrypt(chipperTextSingle, nonceOut, secKeyA);
            totalTime += System.nanoTime() - startTime;
        }
        long decryptSingle = totalTime/(iterations*1000);
        Log.d(TAG, "DualSalt.decrypt execution time: " + decryptSingle + "µs");

        totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            byte[] d1 = DualSalt.decryptDual1(chipperTextDual, secKeyA);
            DualSalt.decryptDual2(d1, chipperTextDual, nonceOut, secKeyB);
            totalTime += System.nanoTime() - startTime;
        }
        long decryptDual = totalTime/(iterations*1000);
        Log.d(TAG, "DualSalt.decryptDual execution time: " + decryptDual + "µs " + decryptDual*100/decryptSingle + "%");
    }

    private void start() {
        (new Thread(() -> {
            Log.d(TAG, "start test");

            try {
                testSignSpeed();
                testDecryptSpeed();

            } catch (Exception e) {
                e.printStackTrace();
            }

            Log.d(TAG, "test done");

        })).start();

    }

    public static void main(String[] args) {
        DualSaltSpeedTest t = new DualSaltSpeedTest();
        t.start();
    }
}
