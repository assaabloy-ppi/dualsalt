package dualsalt;

import java.util.Arrays;

public class example {

    public static void main(String[] args) {
        byte[] pubKeyPartA = new byte[DualSalt.publicKeyPartLength];
        byte[] secKeyPartA = new byte[DualSalt.secretKeyPartLength];
        DualSalt.createKeyPart(pubKeyPartA, secKeyPartA, random(32));

        byte[] pubKeyPartB = new byte[DualSalt.publicKeyPartLength];
        byte[] secKeyPartB = new byte[DualSalt.secretKeyPartLength];
        DualSalt.createKeyPart(pubKeyPartB, secKeyPartB, random(32));

        byte[] message = random(10);

        // Calculate a virtual key
        byte[] virtualPublicKey = DualSalt.addPublicKeyParts(pubKeyPartA, pubKeyPartB);

        // Sign for the virtual key with the two secret key parts
        byte[] nonceA = random(32);
        byte[] m1 = DualSalt.signCreateDual1(message, secKeyPartA, virtualPublicKey, nonceA);
        byte[] m2 = DualSalt.signCreateDual2(m1, secKeyPartB, random(32));
        byte[] signature = DualSalt.signCreateDual3(m1, m2, secKeyPartA, nonceA);
        System.out.println(DualSalt.signVerify(signature, virtualPublicKey));

        // Decrypt data encrypted for the virtual key with the two secret key parts
        byte[] cipherMessage = DualSalt.encrypt(message, virtualPublicKey, random(32));
        byte[] d1 = DualSalt.decryptDual1(cipherMessage, secKeyPartB);
        byte[] decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, secKeyPartA);
        System.out.println(Arrays.equals(message, decryptedMessage));

        // Rotate the two secrt key parts, but they still represent the same virtual key pair.
        byte[] random = random(32);
        byte[] newSecKeyPartA = DualSalt.rotateKeyPart(secKeyPartA, random, true);
        byte[] newSecKeyPartB = DualSalt.rotateKeyPart(secKeyPartB, random, false);

        // Sign for the virtual key with the two new secret key parts
        nonceA = random(32);
        m1 = DualSalt.signCreateDual1(message, newSecKeyPartA, virtualPublicKey, nonceA);
        m2 = DualSalt.signCreateDual2(m1, newSecKeyPartB, random(32));
        signature = DualSalt.signCreateDual3(m1, m2, newSecKeyPartA, nonceA);
        System.out.println(DualSalt.signVerify(signature, virtualPublicKey));

        // Decrypt data encrypted for the virtual key with the two new secret key parts
        cipherMessage = DualSalt.encrypt(message, virtualPublicKey, random(32));
        d1 = DualSalt.decryptDual1(cipherMessage, newSecKeyPartB);
        decryptedMessage = DualSalt.decryptDual2(d1, cipherMessage, newSecKeyPartA);
        System.out.println(Arrays.equals(message, decryptedMessage));
    }

    private static byte[] random(int length) {
        return TweetNaclFast.randombytes(length);
    }
}
