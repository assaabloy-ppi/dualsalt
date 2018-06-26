package dualsalt.tests;

import dualsalt.DualSalt;
import dualsalt.TweetNaclFast;

import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;

import static java.lang.String.join;

public class CreateTestVectors {

    private File clearFile(String fileName) throws Exception {
        String testPath = "src\\dualsalt\\tests\\";
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
            byte[] keySeedA = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeedA, DualSalt.seedLength);
            byte[] secretPartA = new byte[DualSalt.secretKeyLength];
            byte[] publicPartA = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicPartA, secretPartA, keySeedA);

            byte[] keySeedB = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeedB, DualSalt.seedLength);
            byte[] secretPartB = new byte[DualSalt.secretKeyLength];
            byte[] publicPartB = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicPartB, secretPartB, keySeedB);

            byte[] virtualPublicKey = DualSalt.addPublicKeys(publicPartA, publicPartB);

            byte [] message =  new byte[messageLength];
            TweetNaclFast.randombytes(message, messageLength);

            byte[] m1 = DualSalt.signCreateDual1(message,virtualPublicKey, secretPartA);
            byte[] m2 = DualSalt.signCreateDual2(m1, secretPartB);
            byte[] signature = DualSalt.signCreateDual3(m1, m2, publicPartA, secretPartA);

            if (!DualSalt.signVerify(signature, virtualPublicKey)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeedA),
                    TweetNaclFast.hexEncodeToString(publicPartA),
                    TweetNaclFast.hexEncodeToString(keySeedB),
                    TweetNaclFast.hexEncodeToString(publicPartB),
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
            byte[] keySeed = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeed, DualSalt.seedLength);
            byte[] secretKey = new byte[DualSalt.secretKeyLength];
            byte[] publicKey = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicKey, secretKey, keySeed);

            byte[] tempKeySeed = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(tempKeySeed, DualSalt.seedLength);

            byte [] nonce =  new byte[DualSalt.nonceLength];
            TweetNaclFast.randombytes(nonce, DualSalt.nonceLength);
            byte [] nonceOut =  new byte[DualSalt.nonceLength];

            byte [] message =  new byte[messageLength];
            TweetNaclFast.randombytes(message, messageLength);

            byte[] chipperText = DualSalt.encrypt(message, nonce, publicKey, tempKeySeed);
            byte[] messageOut = DualSalt.decrypt(chipperText, nonceOut, secretKey);


            if (!Arrays.equals(message, messageOut) ||
                !Arrays.equals(nonce, nonceOut)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeed),
                    TweetNaclFast.hexEncodeToString(publicKey),
                    TweetNaclFast.hexEncodeToString(tempKeySeed),
                    TweetNaclFast.hexEncodeToString(nonce),
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
            byte[] keySeedA = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeedA, DualSalt.seedLength);
            byte[] secretPartA = new byte[DualSalt.secretKeyLength];
            byte[] publicPartA = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicPartA, secretPartA, keySeedA);

            byte[] keySeedB = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeedB, DualSalt.seedLength);
            byte[] secretPartB = new byte[DualSalt.secretKeyLength];
            byte[] publicPartB = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicPartB, secretPartB, keySeedB);

            byte[] virtualPublicKey = DualSalt.addPublicKeys(publicPartA, publicPartB);

            byte[] tempKeySeed = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(tempKeySeed, DualSalt.seedLength);

            byte [] nonce =  new byte[DualSalt.nonceLength];
            TweetNaclFast.randombytes(nonce, DualSalt.nonceLength);
            byte [] nonceOut =  new byte[DualSalt.nonceLength];

            byte [] message =  new byte[messageLength];
            TweetNaclFast.randombytes(message, messageLength);

            byte[] chipperText = DualSalt.encrypt(message, nonce, virtualPublicKey, tempKeySeed);
            byte[] d1 = DualSalt.decryptDual1(chipperText, secretPartA);
            byte[] messageOut = DualSalt.decryptDual2(d1, chipperText, nonceOut, secretPartB);

            if (!Arrays.equals(message, messageOut) ||
                    !Arrays.equals(nonce, nonceOut)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeedA),
                    TweetNaclFast.hexEncodeToString(publicPartA),
                    TweetNaclFast.hexEncodeToString(keySeedB),
                    TweetNaclFast.hexEncodeToString(publicPartB),
                    TweetNaclFast.hexEncodeToString(virtualPublicKey),
                    TweetNaclFast.hexEncodeToString(tempKeySeed),
                    TweetNaclFast.hexEncodeToString(nonce),
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
            byte[] keySeedA = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeedA, DualSalt.seedLength);
            byte[] secretPartA = new byte[DualSalt.secretKeyLength];
            byte[] publicPartA = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicPartA, secretPartA, keySeedA);

            byte[] keySeedB = new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(keySeedB, DualSalt.seedLength);
            byte[] secretPartB = new byte[DualSalt.secretKeyLength];
            byte[] publicPartB = new byte[DualSalt.publicKeyLength];
            DualSalt.createKeyPair(publicPartB, secretPartB, keySeedB);

            byte[] virtualPublicKey = DualSalt.addPublicKeys(publicPartA, publicPartB);

            byte [] rotateRandom =  new byte[DualSalt.seedLength];
            TweetNaclFast.randombytes(rotateRandom, DualSalt.seedLength);

            byte[] newPublicPartA = new byte[DualSalt.publicKeyLength];
            byte[] newPublicPartB = new byte[DualSalt.publicKeyLength];
            DualSalt.rotateKey(newPublicPartA, secretPartA, rotateRandom, true);
            DualSalt.rotateKey(newPublicPartB, secretPartB, rotateRandom, false);

            byte[] newVirtualPublicKey = DualSalt.addPublicKeys(newPublicPartA, newPublicPartB);

            if (!Arrays.equals(virtualPublicKey, newVirtualPublicKey)) {
                throw new Exception();
            }

            out.write(join(":",
                    TweetNaclFast.hexEncodeToString(keySeedA),
                    TweetNaclFast.hexEncodeToString(publicPartA),
                    TweetNaclFast.hexEncodeToString(keySeedB),
                    TweetNaclFast.hexEncodeToString(publicPartB),
                    TweetNaclFast.hexEncodeToString(virtualPublicKey),
                    TweetNaclFast.hexEncodeToString(rotateRandom),
                    TweetNaclFast.hexEncodeToString(secretPartA),
                    TweetNaclFast.hexEncodeToString(secretPartB)
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
