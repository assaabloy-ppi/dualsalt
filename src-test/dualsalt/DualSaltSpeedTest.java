package dualsalt;

import org.junit.Test;

public class DualSaltSpeedTest {

    private long measureMeanMicroS(int iterations, Runnable dut){
        long totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            dut.run();
            totalTime += System.nanoTime() - startTime;
        }
        return totalTime/(iterations*1000);
    }

    @Test
    public void testSignSpeed() {
        System.out.println("\nTest sign speed");

        byte[] rand1 = TweetNaclFast.hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
        byte[] rand2 = TweetNaclFast.hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
        byte[] rand3 = TweetNaclFast.hexDecode("a39837c4d2d5300daebbd532df20f8135ac49000da11249ea3510941703a7e21");
        byte[] rand4 = TweetNaclFast.hexDecode("a99cbc5e4995afd8c14adb49410ecd957aecc8d02e56f0eef73ade8f79bc1d16");

        byte[] pubKeyA = new byte[DualSalt.publicKeyPartLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyPartLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyPartLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyPartLength];
        DualSalt.createKeyPart(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPart(pubKeyB, secKeyB, rand2);
        byte[] virtualPublicKey = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

        byte[] pubKeyC = new byte[DualSalt.publicKeyLength];
        byte[] secKeyC = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyC, secKeyC, rand1);

        String testString = "Fy fabian vad jag vill ha en ny dator";
        byte[] message = testString.getBytes();
        byte[] signature = DualSalt.signCreate(message, secKeyC);

        byte[] tweetSecretKeyA = new byte[64];
        System.arraycopy(rand1, 0, tweetSecretKeyA, 0 , DualSalt.seedLength);
        System.arraycopy(pubKeyA, 0, tweetSecretKeyA, DualSalt.seedLength, DualSalt.publicKeyLength);
        byte[] sm = new byte[message.length + 64];
        byte[] tmp = new byte[sm.length];
        int iterations = 1000;

        long signRef = measureMeanMicroS(iterations, () ->
              TweetNaclFast.crypto_sign(sm, -1, message, 0, message.length, tweetSecretKeyA)
        );
        System.out.println("TweetNaclFast.crypto_sign execution time: " + signRef + "µs");

        long signSingle = measureMeanMicroS(iterations, () ->
            DualSalt.signCreate(message, secKeyC)
        );
        System.out.println( "DualSalt.signCreate execution time: " + signSingle + "µs " + signSingle*100/signRef + "%");

        long signDual = measureMeanMicroS(iterations, () -> {
            byte[] m1 = DualSalt.signCreateDual1(message, secKeyA, virtualPublicKey, rand3);
            byte[] m2 = DualSalt.signCreateDual2(m1, secKeyB, rand4);
            DualSalt.signCreateDual3(m1, m2, secKeyA, rand3);
        });
        System.out.println("DualSalt.signCreateDual execution time: " + signDual + "µs " + signDual*100/signRef + "%");

        long verifyRef = measureMeanMicroS(iterations, () ->
                TweetNaclFast.crypto_sign_open(tmp, 0, signature, 0, signature.length, pubKeyA)
        );
        System.out.println("TweetNaclFast.crypto_sign_open execution time: " + verifyRef + "µs");

        long verify = measureMeanMicroS(iterations, () ->
                DualSalt.signVerify(signature, pubKeyC)
        );
        System.out.println("DualSalt.signVerify execution time: " + verify + "µs " + verify*100/verifyRef + "%");
    }

    @Test
    public void testDecryptSpeed() {
        System.out.println("\nTest decrypt speed");

        byte[] rand1 = TweetNaclFast.hexDecode("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
        byte[] rand2 = TweetNaclFast.hexDecode("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
        byte[] rand3 = TweetNaclFast.hexDecode("E14A55160C418542BFB0B4DCEB4CAA489A09AF8B9F61104F27E621BCB5002388");

        byte[] pubKeyA = new byte[DualSalt.publicKeyPartLength];
        byte[] pubKeyB = new byte[DualSalt.publicKeyPartLength];
        byte[] secKeyA = new byte[DualSalt.secretKeyPartLength];
        byte[] secKeyB = new byte[DualSalt.secretKeyPartLength];
        DualSalt.createKeyPart(pubKeyA, secKeyA, rand1);
        DualSalt.createKeyPart(pubKeyB, secKeyB, rand2);
        byte[] virtualPublicKey = DualSalt.addPublicKeyParts(pubKeyA, pubKeyB);

        byte[] pubKeyC = new byte[DualSalt.publicKeyLength];
        byte[] secKeyC = new byte[DualSalt.secretKeyLength];
        DualSalt.createKeyPair(pubKeyC, secKeyC, rand1);

        String testString = "Fy fabian vad jag vill ha en ny dator";
        byte[] message = testString.getBytes();
        byte[] chipperTextSingle = DualSalt.encrypt(message, pubKeyC, rand3);
        byte[] chipperTextDual = DualSalt.encrypt(message, virtualPublicKey, rand3);
        int iterations = 1000;

        long encrypt = measureMeanMicroS(iterations, () ->
            DualSalt.encrypt(message, pubKeyC, rand3)
        );
        System.out.println("DualSalt.encrypt execution time: " + encrypt + "µs");

        long decryptSingle = measureMeanMicroS(iterations, () ->
                DualSalt.decrypt(chipperTextSingle, secKeyC)
        );
        System.out.println("DualSalt.decrypt execution time: " + decryptSingle + "µs");

        long decryptDual = measureMeanMicroS(iterations, () -> {
            byte[] d1 = DualSalt.decryptDual1(chipperTextDual, secKeyA);
            DualSalt.decryptDual2(d1, chipperTextDual, secKeyB);
        });
        System.out.println("DualSalt.decryptDual execution time: " + decryptDual + "µs " + decryptDual*100/decryptSingle + "%");
    }
}
