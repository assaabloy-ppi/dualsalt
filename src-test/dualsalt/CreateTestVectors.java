package dualsalt;

import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;

import static java.lang.String.join;

public class CreateTestVectors {

    private File clearFile(String fileName) throws Exception {
        String testPath = "src-test\\dualsalt\\";
        File file = new File(testPath + fileName);
        if (file.exists()) {
            if (!file.delete()) {
                throw new Exception("Can not delete file");
            }
        }
        return file;
    }

    private void createSignDualTestVector() throws Exception {
        String fileName = "signDual.input";
        int startMessageLength = 0;
        int messageLengthIncrease = 1;
        int numberOfTestVectors = 1024;

        File file = clearFile(fileName);

        FileWriter out = new FileWriter(file);

        int messageLength = startMessageLength;
        for(int ii=1; ii<=numberOfTestVectors; ii++){
            byte[] keySeedA = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte[] secretPartA = new byte[DualSalt.dualSecretKeyLength];
            byte[] publicPartA = new byte[DualSalt.dualPublicKeyLength];
            DualSalt.createDualKeyPair(publicPartA, secretPartA, keySeedA);

            byte[] keySeedB = TweetNaclFast.randombytes( DualSalt.seedLength);
            byte[] secretPartB = new byte[DualSalt.dualSecretKeyLength];
            byte[] publicPartB = new byte[DualSalt.dualPublicKeyLength];
            DualSalt.createDualKeyPair(publicPartB, secretPartB, keySeedB);

            byte[] virtualPublicKey = DualSalt.addPublicKeyParts(publicPartA, publicPartB);

            byte [] message = TweetNaclFast.randombytes(messageLength);
            byte [] randA = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte [] randB = TweetNaclFast.randombytes(DualSalt.seedLength);

            byte[] m1 = DualSalt.signCreateDual1(message, secretPartA, virtualPublicKey, randA);
            byte[] m2 = DualSalt.signCreateDual2(m1, secretPartB, randB);
            byte[] signature = DualSalt.signCreateDual3(m1, m2, secretPartA, randA);

            if (!DualSalt.signVerify(signature, virtualPublicKey)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeedA),
                    TweetNaclFast.hexEncodeToString(publicPartA),
                    TweetNaclFast.hexEncodeToString(randA),
                    TweetNaclFast.hexEncodeToString(keySeedB),
                    TweetNaclFast.hexEncodeToString(publicPartB),
                    TweetNaclFast.hexEncodeToString(randB),
                    TweetNaclFast.hexEncodeToString(virtualPublicKey),
                    TweetNaclFast.hexEncodeToString(message),
                    TweetNaclFast.hexEncodeToString(signature)
                    + "\r\n"
            ));

            messageLength += messageLengthIncrease;
        }

        out.close();
    }

    private void createDecryptTestVector() throws Exception {
        String fileName = "decrypt.input";
        int startMessageLength = 0;
        int messageLengthIncrease = 1;
        int numberOfTestVectors = 1024;

        File file = clearFile(fileName);

        FileWriter out = new FileWriter(file);

        int messageLength = startMessageLength;
        for(int ii=1; ii<=numberOfTestVectors; ii++){
            byte[] keySeed = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte[] secretKey = new byte[DualSalt.secretKeyLength];
            byte[] publicKey = new byte[DualSalt.publicKeyLength];
            DualSalt.createSingleKeyPair(publicKey, secretKey, keySeed);

            byte[] tempKeySeed = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte [] message =  TweetNaclFast.randombytes( messageLength);

            byte[] chipperText = DualSalt.encrypt(message, publicKey, tempKeySeed);
            byte[] messageOut = DualSalt.decrypt(chipperText, secretKey);


            if (!Arrays.equals(message, messageOut)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeed),
                    TweetNaclFast.hexEncodeToString(publicKey),
                    TweetNaclFast.hexEncodeToString(tempKeySeed),
                    TweetNaclFast.hexEncodeToString(message),
                    TweetNaclFast.hexEncodeToString(chipperText)
                            + "\r\n"
            ));

            messageLength += messageLengthIncrease;
        }

        out.close();
    }

    private void createDecryptDualTestVector() throws Exception {
        String fileName = "decryptDual.input";
        int startMessageLength = 0;
        int messageLengthIncrease = 1;
        int numberOfTestVectors = 1024;

        File file = clearFile(fileName);

        FileWriter out = new FileWriter(file);

        int messageLength = startMessageLength;
        for(int ii=1; ii<=numberOfTestVectors; ii++){
            byte[] keySeedA = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte[] secretPartA = new byte[DualSalt.dualSecretKeyLength];
            byte[] publicPartA = new byte[DualSalt.dualPublicKeyLength];
            DualSalt.createDualKeyPair(publicPartA, secretPartA, keySeedA);

            byte[] keySeedB = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte[] secretPartB = new byte[DualSalt.dualSecretKeyLength];
            byte[] publicPartB = new byte[DualSalt.dualPublicKeyLength];
            DualSalt.createDualKeyPair(publicPartB, secretPartB, keySeedB);

            byte[] virtualPublicKey = DualSalt.addPublicKeyParts(publicPartA, publicPartB);

            byte[] tempKeySeed = TweetNaclFast.randombytes(DualSalt.seedLength);

            byte [] message = TweetNaclFast.randombytes(messageLength);

            byte[] chipperText = DualSalt.encrypt(message, virtualPublicKey, tempKeySeed);
            byte[] d1 = DualSalt.decryptDual1(chipperText, secretPartA);
            byte[] messageOut = DualSalt.decryptDual2(d1, chipperText, secretPartB);

            if (!Arrays.equals(message, messageOut)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeedA),
                    TweetNaclFast.hexEncodeToString(publicPartA),
                    TweetNaclFast.hexEncodeToString(keySeedB),
                    TweetNaclFast.hexEncodeToString(publicPartB),
                    TweetNaclFast.hexEncodeToString(virtualPublicKey),
                    TweetNaclFast.hexEncodeToString(tempKeySeed),
                    TweetNaclFast.hexEncodeToString(message),
                    TweetNaclFast.hexEncodeToString(chipperText)
                            + "\r\n"
            ));

            messageLength += messageLengthIncrease;
        }

        out.close();
    }

    private void createKeyRotateTestVector() throws Exception {
        String fileName = "keyRotate.input";
        int numberOfTestVectors = 1024;

        File file = clearFile(fileName);

        FileWriter out = new FileWriter(file);

        for(int ii=1; ii<=numberOfTestVectors; ii++){
            byte[] keySeedA = TweetNaclFast.randombytes( DualSalt.seedLength);
            byte[] secretKeyA = new byte[DualSalt.dualSecretKeyLength];
            byte[] publicKeyA = new byte[DualSalt.dualPublicKeyLength];
            DualSalt.createDualKeyPair(publicKeyA, secretKeyA, keySeedA);

            byte[] keySeedB = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte[] secretKeyB = new byte[DualSalt.dualSecretKeyLength];
            byte[] publicKeyB = new byte[DualSalt.dualPublicKeyLength];
            DualSalt.createDualKeyPair(publicKeyB, secretKeyB, keySeedB);

            byte[] virtualPublicKey = DualSalt.addPublicKeyParts(publicKeyA, publicKeyB);

            byte [] rotateRandom = TweetNaclFast.randombytes(DualSalt.seedLength);
            byte[] newSecretA = DualSalt.rotateKey(secretKeyA, rotateRandom, true);
            byte[] newSecretB = DualSalt.rotateKey(secretKeyB, rotateRandom, false);

            byte[] newPublicKeyA = Arrays.copyOfRange(newSecretA, 32, 64);
            byte[] newPublicKeyB = Arrays.copyOfRange(newSecretB, 32, 64);
            byte[] newVirtualPublicKey = DualSaltTest.addGroupElements(newPublicKeyA, newPublicKeyB);

            if (!Arrays.equals(virtualPublicKey, newVirtualPublicKey)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeedA),
                    TweetNaclFast.hexEncodeToString(publicKeyA),
                    TweetNaclFast.hexEncodeToString(keySeedB),
                    TweetNaclFast.hexEncodeToString(publicKeyB),
                    TweetNaclFast.hexEncodeToString(virtualPublicKey),
                    TweetNaclFast.hexEncodeToString(rotateRandom),
                    TweetNaclFast.hexEncodeToString(newSecretA),
                    TweetNaclFast.hexEncodeToString(newSecretB)
                            + "\r\n"
            ));
        }

        out.close();
    }

    private void run() throws Exception {
        createSignDualTestVector();
        createDecryptTestVector();
        createDecryptDualTestVector();
        createKeyRotateTestVector();
    }

    public static void main(String[] args) throws Exception {
        CreateTestVectors t = new CreateTestVectors();
        t.run();
    }
}
