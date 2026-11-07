package org.vince.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Narrow workaround for newly encrypted messages on Vince only.
 * It does not modify Android, TEE, root, or arbitrary existing ciphertext.
 * Confirm via ephemeral hardware-backed test first; not portable.
 */
public final class VinceOaepCompat {
    private VinceOaepCompat() {}
    private static final OAEPParameterSpec WIRE =
      new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
          PSource.PSpecified.DEFAULT);

    public static byte[] encryptNewMessage(PublicKey key, byte[] data)
        throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.ENCRYPT_MODE, key, WIRE);
        return c.doFinal(data);
    }

    public static byte[] decryptOnVerifiedVince(PrivateKey hardwareKey, byte[] data)
        throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, hardwareKey);
        return c.doFinal(data);
    }
}
