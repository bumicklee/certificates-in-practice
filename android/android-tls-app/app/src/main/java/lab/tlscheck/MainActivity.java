package lab.tlscheck;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * 강의 데모용 디버그 앱: 사례 하나마다 HTTPS GET 한 번을 하고, 결과 한 줄을 로그(TlsLab)와 화면에 낸다.
 * 실행: adb shell am start -n lab.tlscheck/.MainActivity --es case <system|nsc|wrongname|unknownroot|pin|mtls-none|mtls-cert>
 * 포트(맥 쪽 openssl s_server, adb reverse로 연결): 18460 정상 · 18461 이름 다름 · 18462 모르는 루트 · 18463 mTLS
 */
public class MainActivity extends Activity {
    static final String TAG = "TlsLab";
    TextView tv;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        tv = new TextView(this);
        tv.setTextSize(20);
        tv.setPadding(40, 40, 40, 40);
        // Android 15는 화면 끝까지 그린다: 바깥 틀이 상태 표시줄만큼 비우고, 글은 그 안에서 여백을 둔다
        android.widget.FrameLayout root = new android.widget.FrameLayout(this);
        root.setFitsSystemWindows(true);
        root.addView(tv);
        setContentView(root);
        run(getIntent());
    }

    @Override protected void onNewIntent(Intent i) { super.onNewIntent(i); setIntent(i); run(i); }

    void run(Intent i) {
        final String c = i.getStringExtra("case") == null ? "nsc" : i.getStringExtra("case");
        tv.setText("case=" + c + " …");
        new Thread(() -> {
            String line = "case=" + c + " nsc=" + getString(R.string.lab_nsc) + " " + doCase(c);
            Log.i(TAG, line);
            runOnUiThread(() -> tv.setText(line));
        }).start();
    }

    String doCase(String c) {
        String url;
        SSLContext ctx = null;
        try {
            switch (c) {
                case "system":      url = "https://127.0.0.1:18460/"; break; // NSC domain-config 밖 → 시스템 루트만
                case "nsc":         url = "https://localhost:18460/"; break;
                case "wrongname":   url = "https://localhost:18461/"; break;
                case "unknownroot": url = "https://localhost:18462/"; break;
                case "pin":         url = "https://localhost:18460/"; break;
                case "mtls-none":   url = "https://localhost:18463/"; break;
                case "mtls-cert":   url = "https://localhost:18463/"; ctx = clientCertContext(); break;
                default: return "FAIL unknown case";
            }
        } catch (Exception e) {
            return "FAIL setup " + describe(e);
        }
        HttpsURLConnection conn = null;
        try {
            conn = (HttpsURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            if (ctx != null) conn.setSSLSocketFactory(ctx.getSocketFactory());
            int code = conn.getResponseCode();
            try (InputStream in = conn.getInputStream()) { while (in.read() != -1) { } }
            return "url=" + url + " OK HTTP " + code;
        } catch (Exception e) {
            return "url=" + url + " FAIL " + describe(e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** 실습 클라이언트 키를 assets의 PKCS#12에서 읽어 KeyManager로 쓴다. 신뢰는 기본(NSC)을 그대로 쓴다.
     *  실제 앱이라면 키를 Android Keystore/KeyChain에 두고 내보낼 수 없게 한다. */
    SSLContext clientCertContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = getAssets().open("client.p12")) { ks.load(in, "lab-only-pass".toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "lab-only-pass".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null); // null = 앱 기본 신뢰(NSC를 따름)
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    static String describe(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) root = root.getCause();
        String s = e.getClass().getName() + ": " + e.getMessage();
        if (root != e) s += " | root=" + root.getClass().getName() + ": " + root.getMessage();
        return s;
    }
}
