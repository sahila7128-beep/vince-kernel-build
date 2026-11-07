import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.vince.crypto.VinceOaepCompat;

/** Software control; does not replace hardware Keymaster testing. */
public final class HostCompatTest {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        byte[] input = "vince-oaep".getBytes(StandardCharsets.UTF_8);
        byte[] ct = VinceOaepCompat.encryptNewMessage(kp.getPublic(), input);
        Cipher d = Cipher.getInstance("RSA/ECB/OAEPPadding");
        d.init(Cipher.DECRYPT_MODE, kp.getPrivate(),
          new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
              PSource.PSpecified.DEFAULT));
        if(!Arrays.equals(input, d.doFinal(ct))) throw new AssertionError("roundtrip");
        System.out.println("PASS: software SHA256/MGF1-SHA256 interop");
    }
}
