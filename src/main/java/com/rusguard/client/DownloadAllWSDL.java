package com.rusguard.client;

import javax.net.ssl.*;
import java.io.*;
import java.lang.Exception;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DownloadAllWSDL {

    private static Set<String> downloadedUrls = new HashSet<>();

    public static void main(String[] args) throws java.lang.Exception {
        // Отключаем SSL проверку
        disableSSL();

        String baseUrl = "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";
        String wsdlUrl = baseUrl + "?wsdl";

        System.out.println("Скачивание всех файлов WSDL...");
        downloadRecursive(wsdlUrl, "rusguard.wsdl");

        System.out.println("Готово! Скачано файлов: " + downloadedUrls.size());
    }

    private static void downloadRecursive(String url, String localFile) throws java.lang.Exception {
        if (downloadedUrls.contains(url)) {
            return;
        }
        downloadedUrls.add(url);

        System.out.println("Скачивание: " + url + " -> " + localFile);

        // Скачиваем файл
        String content;
        try (InputStream in = new URL(url).openStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }

            content = out.toString("UTF-8");

            // Сохраняем файл
            try (FileWriter writer = new FileWriter(localFile)) {
                writer.write(content);
            }

        } catch (java.lang.Exception e) {
            System.err.println("Ошибка при скачивании " + url + ": " + e.getMessage());
            return;
        }

        // Ищем ссылки на другие файлы в контенте
        Pattern pattern = Pattern.compile("(location\\s*=\\s*\"|schemaLocation\\s*=\\s*\")([^\"]+\\.(xsd|wsdl))\"");
        Matcher matcher = pattern.matcher(content);

        while (matcher.find()) {
            String refUrl = matcher.group(2);

            // Если относительный URL, делаем абсолютным
            if (!refUrl.startsWith("http")) {
                if (refUrl.startsWith("/")) {
                    refUrl = "https://scud-1.gaz.ru" + refUrl;
                } else {
                    // Определяем базовый URL
                    int lastSlash = url.lastIndexOf('/');
                    if (lastSlash > 0) {
                        String base = url.substring(0, lastSlash + 1);
                        refUrl = base + refUrl;
                    }
                }
            }

            // Создаем имя локального файла
            String localName = refUrl
                    .replace("http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc?", "")
                    .replace("?", "_")
                    .replace("/", "_")
                    .replace(":", "_");

            if (localName.length() > 100) {
                localName = "file_" + downloadedUrls.size() + ".xsd";
            }

            // Рекурсивно скачиваем
            downloadRecursive(refUrl, localName);
        }
    }

    private static void disableSSL() {
        try {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            }, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            System.out.println("SSL проверка отключена");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}