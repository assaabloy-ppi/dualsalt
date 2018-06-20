package dualsalt.tests;

import dualsalt.DualSalt;
import dualsalt.TweetNaclFast;

import java.io.File;
import java.io.FileWriter;

import static java.lang.String.join;

public class CreateTestVectors {

    private String testPath = "src\\dualsalt\\tests\\";

    private void createDualSignTestVector() throws Exception {
        String fileName = "signDual.input";
        int startMessageLength = 0;
        int messageLengthIncrease = 1;
        int numberOfTestVectors = 1024;

        File file = new File(testPath + fileName);
        if (file.exists())
        {
            file.delete();
        }

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

    private void run() throws Exception {
        createDualSignTestVector();
    }

    public static void main(String[] args) throws Exception {
        CreateTestVectors t = new CreateTestVectors();
        t.run();
    }
}
