package kvo.rusguard.client;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class SSLUtils {
    // Отключаем проверку SSL сертификатов
    public static void disableSSLVerification() {
        try {
            // Создаем доверенный менеджер, который не проверяет сертификаты
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                            // Не проверяем клиентские сертификаты
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                            // Не проверяем серверные сертификаты
                        }
                    }
            };

            // Устанавливаем наш доверенный менеджер
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Создаем верификатор, который принимает все хосты
            HostnameVerifier allHostsValid = (hostname, session) -> true;

            // Устанавливаем наш верификатор хостов
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}