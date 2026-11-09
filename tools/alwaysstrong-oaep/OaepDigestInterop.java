import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Independent desktop-JCA interoperability regression for Vince.
 *
 * Android Keystore RSA-OAEP SHA-256 defaults MGF1 to SHA-1 (AOSP).
 * TEESimulator-RS v307 instead defaulted MGF1 to the main digest,
 * SHA-256, causing BadPaddingException when ciphertext came from
 * Android Keystore with its SHA-1 MGF1 default.
 *
 * This executable proves the algorithm mismatch on a test RSA key,
 * NOT a particular handset's Keystore, TEE, kernel or app behavior.
 */
public final class OaepDigestInterop {
    private static OAEPParameterSpec oaep(String mainDigest, String mgfDigest) {
        return new OAEPParameterSpec(mainDigest, "MGF1",
            new MGF1ParameterSpec(mgfDigest), PSource.PSpecified.DEFAULT);
    }

    private static byte[] apply(int operation, KeyPair keyPair,
                                byte[] bytes, OAEPParameterSpec params)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(operation, operation == Cipher.ENCRYPT_MODE
            ? keyPair.getPublic() : keyPair.getPrivate(), params);
        return cipher.doFinal(bytes);
    }

    private static void roundTrip(KeyPair keyPair, byte[] plaintext,
                                  String mainDigest, String mgfDigest)
            throws Exception {
        OAEPParameterSpec params = oaep(mainDigest, mgfDigest);
        byte[] encrypted = apply(Cipher.ENCRYPT_MODE, keyPair, plaintext, params);
        byte[] recovered = apply(Cipher.DECRYPT_MODE, keyPair, encrypted, params);
        if (!Arrays.equals(plaintext, recovered)) {
            throw new AssertionError("Roundtrip mismatch for " + mainDigest
                + "/MGF1(" + mgfDigest + ")");
        }
    }

    public static void main(String[] ignored) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair key = generator.generateKeyPair();
        byte[] plaintext = "Vince KeyMint MGF1 interoperability regression"
            .getBytes(StandardCharsets.UTF_8);

        // Correct Android Keystore default: main SHA-256, MGF1 SHA-1.
        OAEPParameterSpec android = oaep("SHA-256", "SHA-1");
        byte[] ciphertext = apply(Cipher.ENCRYPT_MODE, key, plaintext, android);
        byte[] recovered = apply(Cipher.DECRYPT_MODE, key, ciphertext, android);
        if (!Arrays.equals(plaintext, recovered)) {
            throw new AssertionError("Default Android OAEP roundtrip failed");
        }
        System.out.println("PASS: Android Keystore SHA-256/MGF1-SHA-1 roundtrip");

        // v307's old wrong default: SHA-256 for both => must fail on
        // ciphertext encrypted with Android's MGF1 SHA-1 default.
        try {
            byte[] wrong = apply(Cipher.DECRYPT_MODE, key, ciphertext,
                oaep("SHA-256", "SHA-256"));
            throw new AssertionError("Old wrong MGF1 unexpectedly decrypted "
                + wrong.length + " bytes");
        } catch (BadPaddingException expected) {
            System.out.println("PASS: v307 wrong MGF1 digest rejected ciphertext");
        }

        // An explicit SHA-256 MGF1 digest is still valid where authorized.
        roundTrip(key, plaintext, "SHA-256", "SHA-256");
        roundTrip(key, plaintext, "SHA-1", "SHA-1");
        System.out.println("PASS: explicit MGF1-SHA-256 and SHA-1 roundtrips");
        System.out.println("All independent OAEP interoperability checks passed.");
    }
}
