package org.vince.keymintdiagnostic;

import android.app.Activity;
import android.os.Bundle;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyInfo;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Typeface;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class MainActivity extends Activity {
    private final StringBuilder log = new StringBuilder();
    private TextView output;
    private Button run, copy;
    private final String payload = "vince_keymint_diagnostic_2026";
    private static final String TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad,pad,pad,pad);
        layout.setBackgroundColor(0xff10141b);
        TextView title = new TextView(this);
        title.setText("Vince • KeyMint RSA-OAEP Diagnostic\nNo root · No network · No key export");
        title.setTextColor(0xffeef3ff);
        title.setTextSize(18);
        layout.addView(title);

        run = new Button(this);
        run.setText("JALANKAN PENGUJIAN");
        layout.addView(run);
        copy = new Button(this);
        copy.setText("SALIN LAPORAN");
        copy.setEnabled(false);
        layout.addView(copy);

        ScrollView scroll = new ScrollView(this);
        output = new TextView(this);
        output.setTextColor(0xffd0e0ea);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(12);
        output.setText("Tekan JALANKAN PENGUJIAN.\nHasil disimpan hanya di layar sampai disalin.");
        output.setTextIsSelectable(true);
        scroll.addView(output);
        layout.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(layout);

        run.setOnClickListener(v -> {
            run.setEnabled(false);
            copy.setEnabled(false);
            output.setText("Menguji Android Keystore…\n");
            new Thread(() -> {
                synchronized (log) { log.setLength(0); }
                probe();
                runOnUiThread(() -> {
                    output.setText(log.toString());
                    run.setEnabled(true);
                    copy.setEnabled(true);
                });
            }).start();
        });
        copy.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(ClipData.newPlainText("Vince KeyMint diagnostic", log.toString()));
            copy.setText("TERSALIN");
        });
    }

    private void ln(String s) {
        synchronized(log) {log.append(s).append('\n');}
    }

    private String error(Throwable t) {
        StringBuilder s=new StringBuilder();
        int n=0;
        while(t!=null && n<5) {
            if(n>0) s.append(" <- ");
            s.append(t.getClass().getName());
            if(t.getMessage()!=null) s.append(": ").append(t.getMessage().replace('\n',' '));
            t=t.getCause();
            n++;
        }
        return s.toString();
    }

    private static OAEPParameterSpec oaep(String digest,String mgfDigest) {
        return new OAEPParameterSpec(digest,"MGF1",
          "SHA-1".equals(mgfDigest) ? MGF1ParameterSpec.SHA1 : MGF1ParameterSpec.SHA256,
          PSource.PSpecified.DEFAULT);
    }

    private KeyPair makeAndroidKey(String alias, String[] digests) throws Exception {
        KeyPairGenerator g=KeyPairGenerator.getInstance("RSA","AndroidKeyStore");
        KeyGenParameterSpec spec=new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_DECRYPT)
           .setKeySize(2048)
           .setDigests(digests)
           .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
           .build();
        g.initialize(spec);
        return g.generateKeyPair();
    }

    private void hardwareInfo(PrivateKey key) {
        try {
            KeyFactory f=KeyFactory.getInstance(key.getAlgorithm(),"AndroidKeyStore");
            KeyInfo info=f.getKeySpec(key,KeyInfo.class);
            ln("KeyInfo secureHardware="+info.isInsideSecureHardware()
               +(Build.VERSION.SDK_INT>=31 ? " securityLevel="+info.getSecurityLevel():""));
        } catch(Throwable t) {
            ln("KeyInfo unavailable: "+error(t));
        }
    }

    private void tryRoundTrip(String label, KeyPair kp, OAEPParameterSpec spec) {
        ln("\n["+label+"]");
        byte[] cipherText;
        try {
            KeyFactory swFactory=KeyFactory.getInstance("RSA");
            java.security.PublicKey pub=swFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            Cipher enc=Cipher.getInstance(TRANSFORM);
            enc.init(Cipher.ENCRYPT_MODE,pub,spec);
            ln("Encryption provider="+enc.getProvider().getName());
            cipherText=enc.doFinal(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            ln("Encryption OK: ciphertext="+cipherText.length+" bytes");
        } catch(Throwable t) {
            ln("ENCRYPT_FAIL: "+error(t));
            return;
        }
        try {
            Cipher dec=Cipher.getInstance(TRANSFORM);
            dec.init(Cipher.DECRYPT_MODE,kp.getPrivate(),spec);
            ln("Decryption provider="+dec.getProvider().getName());
            byte[] result=dec.doFinal(cipherText);
            boolean ok=java.util.Arrays.equals(result,payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            ln("ROUNDTRIP="+(ok?"PASS":"FAIL")+" decrypted="+result.length);
        } catch(Throwable t) {
            ln("DECRYPT_FAIL: "+error(t));
        }
    }

    private void probeSoftware() {
        ln("\n[SOFTWARE CONTROL]");
        try {
            KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KeyPair kp=g.generateKeyPair();
            tryRoundTrip("software SHA256 + MGF1 SHA1",kp,oaep("SHA-256","SHA-1"));
            tryRoundTrip("software SHA256 + MGF1 SHA256",kp,oaep("SHA-256","SHA-256"));
        } catch(Throwable t) { ln("SOFTWARE_CONTROL_FAIL: "+error(t)); }
    }

    private void probe() {
        ln("VINCE KEYMINT DIAGNOSTIC 1.0");
        ln("When="+new Date().toString());
        ln("Device="+Build.MANUFACTURER+" / "+Build.MODEL+" / "+Build.DEVICE);
        ln("Android API="+Build.VERSION.SDK_INT+" release="+Build.VERSION.RELEASE);
        ln("Test is read-only except temporary AndroidKeyStore aliases, which are deleted.");
        ln("Root permission is not requested. Private keys are never exported.");
        probeSoftware();
        try {
            KeyStore store=KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            String alias="vince_diagnostic_"+System.currentTimeMillis();
            ln("\n[ANDROID KEYSTORE SHA256 / OAEP]");
            try {
                KeyPair kp=makeAndroidKey(alias,new String[]{KeyProperties.DIGEST_SHA256});
                hardwareInfo(kp.getPrivate());
                tryRoundTrip("A: SHA256 + MGF1 SHA1 (Duck Detector exact params)",kp,oaep("SHA-256","SHA-1"));
                tryRoundTrip("B: SHA256 + MGF1 SHA256 (cross-check)",kp,oaep("SHA-256","SHA-256"));
            } catch(Throwable t) {ln("KEYSTORE_GENERATE_FAIL: "+error(t));}
            finally {
                try {store.deleteEntry(alias);ln("Temporary AndroidKeyStore key deleted.");}
                catch(Throwable t) {ln("DELETE_FAIL: "+error(t));}
            }
        } catch(Throwable t) {ln("ANDROID_KEYSTORE_FAIL: "+error(t));}
        ln("\nEND. Share this report only; it contains no keys.");
    }
}
