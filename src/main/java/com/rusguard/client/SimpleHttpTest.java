package com.rusguard.client;

import java.net.HttpURLConnection;
import java.net.URL;

public class SimpleHttpTest {
    public static void main(String[] args) {
        try {
            System.out.println("=== ПРОВЕРКА ДОСТУПНОСТИ СЕРВЕРА ===");

            String url = "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";

            // 1. Проверка доступности
            System.out.println("Проверяем: " + url);
            URL serverUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) serverUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int responseCode = conn.getResponseCode();
            System.out.println("HTTP код: " + responseCode);

            if (responseCode == 200) {
                System.out.println("✅ Сервер доступен");

                // Читаем ответ
                java.io.BufferedReader in = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();

                System.out.println("Ответ сервера (первые 500 символов):");
                System.out.println(content.toString().substring(0, Math.min(500, content.length())));

            } else {
                System.err.println("❌ Сервер вернул ошибку: " + responseCode);
                System.err.println("Сообщение: " + conn.getResponseMessage());
            }

            conn.disconnect();

            // 2. Проверка WSDL
            System.out.println("\n=== ПРОВЕРКА WSDL ===");
            String wsdlUrl = url + "?wsdl";
            System.out.println("Проверяем WSDL: " + wsdlUrl);

            URL wsdl = new URL(wsdlUrl);
            HttpURLConnection wsdlConn = (HttpURLConnection) wsdl.openConnection();
            wsdlConn.setRequestMethod("GET");

            int wsdlCode = wsdlConn.getResponseCode();
            System.out.println("WSDL HTTP код: " + wsdlCode);

            if (wsdlCode == 200) {
                System.out.println("✅ WSDL доступен");

                // Проверяем содержимое
                java.io.BufferedReader wsdlIn = new java.io.BufferedReader(
                        new java.io.InputStreamReader(wsdlConn.getInputStream()));
                String wsdlLine;
                int lineCount = 0;

                System.out.println("\nПервые 10 строк WSDL:");
                while ((wsdlLine = wsdlIn.readLine()) != null && lineCount < 10) {
                    System.out.println(wsdlLine);
                    lineCount++;
                }
                wsdlIn.close();

            } else {
                System.err.println("❌ WSDL недоступен");
            }

            wsdlConn.disconnect();

        } catch (Exception e) {
            System.err.println("\n=== ОШИБКА ===");
            e.printStackTrace();
        }
    }
}