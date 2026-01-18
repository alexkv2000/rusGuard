package com.rusguard.client;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SimpleSoapHttpClient {

    public static void main(String[] args) {
        try {
            System.out.println("=== ПРОСТОЙ HTTP SOAP КЛИЕНТ ===");

            // Пробуем разные endpoint
            String[] endpoints = {
                    "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc",
                    "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc/basic",
                    "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc/soap"
            };

            String username = "KvochkinAY";
            String password = "%*5I1OO4rpE%";

            // Пробуем разные варианты SOAPAction
            String[] soapActions = {
                    "http://www.rusguardsecurity.ru/ILDataService/FindEmployees",
                    "http://tempuri.org/ILNetworkService/FindEmployees",
                    "http://www.rusguardsecurity.ru/ILNetworkService/FindEmployees",
                    "FindEmployees"  // Без полного URI
            };

            // Тестируем разные комбинации
            for (String endpoint : endpoints) {
                for (String soapAction : soapActions) {
                    System.out.println("\n--- Тестируем ---");
                    System.out.println("Endpoint: " + endpoint);
                    System.out.println("SOAPAction: " + soapAction);

                    try {
                        testConnection(endpoint, username, password, soapAction);
                    } catch (Exception e) {
                        System.err.println("Ошибка: " + e.getMessage());
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("\n=== ОШИБКА ===");
            e.printStackTrace();
        }
    }

    private static void testConnection(String endpoint, String username,
                                       String password, String soapAction) throws IOException {

        // 1. Создаем более правильный SOAP запрос
        String soapRequest = createProperSoapRequest(username, password);

        System.out.println("=== SOAP ЗАПРОС ===");
        System.out.println(soapRequest);
        System.out.println("=== КОНЕЦ ЗАПРОСА ===\n");

        // 2. Отправляем HTTP POST
        URL url = new URL(endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        // Настраиваем соединение
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
        connection.setRequestProperty("SOAPAction", soapAction);

        // Важно: Basic Auth через заголовок
        String auth = username + ":" + password;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

        // Добавляем дополнительные заголовки
        connection.setRequestProperty("Accept", "text/xml");
        connection.setRequestProperty("User-Agent", "Java SOAP Client");

        connection.setDoOutput(true);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(30000);

        // Включаем логирование заголовков (для отладки)
        System.out.println("Заголовки запроса:");
        connection.getRequestProperties().forEach((k, v) -> {
            if (k != null && v != null) {
                System.out.println("  " + k + ": " + v);
            }
        });

        // 3. Отправляем тело запроса
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = soapRequest.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
            System.out.println("Отправлено байт: " + input.length);
        }

        // 4. Получаем ответ
        int responseCode = connection.getResponseCode();
        System.out.println("HTTP код ответа: " + responseCode);

        // Показываем заголовки ответа
        System.out.println("Заголовки ответа:");
        connection.getHeaderFields().forEach((k, v) -> {
            if (k != null && v != null) {
                System.out.println("  " + k + ": " + v);
            }
        });

        // Читаем ответ
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(
                        responseCode >= 400 ? connection.getErrorStream() : connection.getInputStream(),
                        StandardCharsets.UTF_8))) {

            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine);
            }
        }

        System.out.println("\n=== SOAP ОТВЕТ ===");

        if (responseCode == 200) {
            System.out.println("✅ УСПЕХ! Сервер ответил:");
            String formattedResponse = formatXml(response.toString());
            System.out.println(formattedResponse);
        } else {
            System.err.println("❌ ОШИБКА HTTP: " + responseCode);
            if (response.length() > 0) {
                String formattedError = formatXml(response.toString());
                System.err.println(formattedError);

                // Анализируем ошибку
                analyzeSoapFault(response.toString());
            }
        }

        connection.disconnect();
    }

    private static String createProperSoapRequest(String username, String password) {
        // Более правильный SOAP запрос с правильным пространством имен
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"" +
                "               xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" +
                "               xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"" +
                "               xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">" +
                "  <soap:Header>" +
                "    <Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" +
                "      <UsernameToken>" +
                "        <Username>" + username + "</Username>" +
                "        <Password>" + password + "</Password>" +
                "      </UsernameToken>" +
                "    </Security>" +
                "  </soap:Header>" +
                "  <soap:Body>" +
                "    <FindEmployees xmlns=\"http://tempuri.org/\">" +
                "      <conditions />" +
                "    </FindEmployees>" +
                "  </soap:Body>" +
                "</soap:Envelope>";
    }

    private static void analyzeSoapFault(String xml) {
        System.out.println("\n=== АНАЛИЗ ОШИБКИ ===");

        // Ищем различные паттерны ошибок
        if (xml.contains("ActionNotSupported")) {
            System.err.println("ОШИБКА: ActionNotSupported - неверный SOAPAction");
            System.err.println("Попробуйте получить WSDL файл для определения правильного SOAPAction:");
            System.err.println("  http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc?wsdl");
            System.err.println("  http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc/basic?wsdl");
            System.err.println("  http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc/soap?wsdl");
        }

        if (xml.contains("EndpointDispatcher")) {
            System.err.println("ОШИБКА: ContractFilter mismatch - несоответствие контракта");
            System.err.println("Возможные причины:");
            System.err.println("  1. Неправильный endpoint");
            System.err.println("  2. Неправильное пространство имен в SOAP запросе");
            System.err.println("  3. Неверная версия SOAP (1.1 vs 1.2)");
        }

        // Пытаемся извлечь текст ошибки
        try {
            int start = xml.indexOf("<faultstring>");
            if (start == -1) start = xml.indexOf("<faultstring xml:lang=");
            if (start > 0) {
                int end = xml.indexOf("</faultstring>", start);
                if (end > start) {
                    String fault = xml.substring(start, end + "</faultstring>".length());
                    System.err.println("Детали ошибки:");
                    System.err.println(formatXml(fault));
                }
            }
        } catch (Exception e) {
            // Игнорируем
        }
    }

    private static String formatXml(String xml) {
        try {
            StringBuilder formatted = new StringBuilder();
            int indent = 0;

            String[] lines = xml.replace("><", ">\n<").split("\n");

            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.startsWith("</")) {
                    indent--;
                }

                formatted.append("  ".repeat(Math.max(0, indent)))
                        .append(line)
                        .append("\n");

                if (line.startsWith("<") && !line.startsWith("</") &&
                        !line.contains("/>") && !line.contains("?>")) {
                    indent++;
                }
            }

            return formatted.toString();
        } catch (Exception e) {
            return xml;
        }
    }
}