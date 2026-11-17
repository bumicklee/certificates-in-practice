package lab.attest;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import java.io.File;
import java.io.FileWriter;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * 강의 데모용 디버그 앱: 서버가 준 챌린지를 넣어 AndroidKeyStore에 EC P-256 키를 만들고,
 * 증명 인증서 사슬을 PEM으로 앱 전용 폴더에 저장한다. 키·인증서 외에는 아무것도 읽거나 보내지 않는다.
 * 실행: adb shell am start -n lab.attest/.MainActivity --es challenge <hex> [--ez strongbox true]
 */
public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        setContentView(tv);
        String hex = getIntent().getStringExtra("challenge");
        boolean sb = getIntent().getBooleanExtra("strongbox", false);
        String alias = sb ? "lab-key-sb" : "lab-key-tee";
        StringBuilder out = new StringBuilder();
        try {
            byte[] challenge = hex != null ? hexToBytes(hex) : "no-challenge-given".getBytes();
            KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge);
            if (sb) spec.setIsStrongBoxBacked(true);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(spec.build());
            kpg.generateKeyPair();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain(alias);
            File f = new File(getExternalFilesDir(null), alias + "-chain.pem");
            try (FileWriter w = new FileWriter(f)) {
                for (Certificate c : chain) {
                    w.write("-----BEGIN CERTIFICATE-----\n");
                    w.write(Base64.encodeToString(c.getEncoded(), Base64.DEFAULT));
                    w.write("-----END CERTIFICATE-----\n");
                }
            }
            out.append("OK alias=").append(alias).append(" certs=").append(chain.length).append(" file=").append(f.getAbsolutePath());
        } catch (Exception e) {
            out.append("FAIL alias=").append(alias).append(" ").append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
        }
        Log.i("AttestLab", out.toString());
        tv.setText(out.toString());
    }

    private static byte[] hexToBytes(String s) {
        byte[] r = new byte[s.length() / 2];
        for (int i = 0; i < r.length; i++) r[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return r;
    }
}
