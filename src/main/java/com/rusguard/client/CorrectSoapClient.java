package com.rusguard.client;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class CorrectSoapClient {

    public static void main(String[] args) {
        try {
            System.out.println("=== КОРРЕКТНЫЙ SOAP КЛИЕНТ ===");

            String endpoint = "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";
            String username = "KvochkinAY";
            String password = "%*5I1OO4rpE%";

            // Тест 1: Пробуем через ILDataService порт
            testWithDifferentPorts(endpoint, username, password);

        } catch (Exception e) {
            System.err.println("\n=== ОШИБКА ===");
            e.printStackTrace();
        }
    }

    private static void testWithDifferentPorts(String endpoint, String username, String password) throws Exception {
        // Возможные порты из WSDL
        String[] possiblePorts = {
                "BasicHttpBinding_ILDataService",
                "BasicHttpBinding_ILNetworkService",
                "BasicHttpBinding_ILMonitoringService",
                "BasicHttpBinding_ILSubnetworkSubscribeService",
                "BasicHttpBinding_ILNetworkConfigurationService",
                "BasicHttpBinding_IOperatorContract"
        };

        // Возможные Actions
        String[] possibleActions = {
                "http://www.rusguardsecurity.ru/ILDataService/FindEmployees",
                "http://tempuri.org/ILDataService/FindEmployees",
                "http://www.rusguardsecurity.ru/ILNetworkService/FindEmployees",
                "http://tempuri.org/ILNetworkService/FindEmployees"
        };

        for (String portName : possiblePorts) {
            for (String action : possibleActions) {
                System.out.println("\n" + "=".repeat(60));
                System.out.println("Тест: Порты=" + portName + ", Action=" + action);
                System.out.println("=".repeat(60));

                boolean success = sendSoapRequest(endpoint, username, password, portName, action);

                if (success) {
                    System.out.println("\n✅ НАЙДЕН РАБОЧИЙ КОМБИН!");
                    System.out.println("Порт: " + portName);
                    System.out.println("Action: " + action);
                    return;
                }

                // Пауза между запросами
                Thread.sleep(500);
            }
        }

        System.err.println("\n⚠️  Не найдено рабочей комбинации порт/action");
        System.err.println("Попробуйте другие методы (не findEmployees)");
    }

    private static boolean sendSoapRequest(String endpoint, String username, String password,
                                           String portName, String action) {
        try {
            // Создаем SOAP запрос с учетом порта
            String soapRequest = createSoapRequestForPort(portName, action);

            URL url = new URL(endpoint);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
            connection.setRequestProperty("SOAPAction", action);
            connection.setRequestProperty("Authorization",
                    "Basic " + java.util.Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));

            connection.setDoOutput(true);
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(15000);

            // Отправляем
            try (OutputStream os = connection.getOutputStream()) {
                os.write(soapRequest.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = connection.getResponseCode();

            // Читаем ответ
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(
                            responseCode >= 400 ? connection.getErrorStream() : connection.getInputStream(),
                            StandardCharsets.UTF_8))) {

                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line.trim());
                }
            }

            connection.disconnect();

            if (responseCode == 200) {
                System.out.println("✅ HTTP 200 OK!");

                if (!response.toString().contains("Fault") && !response.toString().contains("faultcode")) {
                    System.out.println("✅ НЕТ SOAP FAULT!");
                    System.out.println("Ответ (первые 300 символов): " +
                            response.substring(0, Math.min(300, response.length())));
                    return true;
                } else {
                    System.out.println("⚠️  Есть SOAP Fault в ответе");
                }
            } else {
                System.out.println("❌ HTTP " + responseCode);

                // Проверяем, изменилась ли ошибка
                if (response.toString().contains("ActionNotSupported")) {
                    System.out.println("Ошибка: ActionNotSupported");
                } else if (response.toString().contains("ContractFilter")) {
                    System.out.println("Ошибка: ContractFilter");
                } else {
                    System.out.println("Другая ошибка");
                }
            }

            return false;

        } catch (Exception e) {
            System.out.println("❌ Исключение: " + e.getClass().getSimpleName());
            return false;
        }
    }

    private static String createSoapRequestForPort(String portName, String action) {
        // Базовый запрос
        String baseRequest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"" +
                "               xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" +
                "               xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">" +
                "  <soap:Body>" +
                "    <FindEmployees xmlns=\"http://www.rusguardsecurity.ru\">" +
                "      <conditions />" +
                "    </FindEmployees>" +
                "  </soap:Body>" +
                "</soap:Envelope>";

        // Если порт ILDataService, возможно нужен другой namespace
        if (portName.contains("ILDataService")) {
            baseRequest = baseRequest.replace(
                    "xmlns=\"http://www.rusguardsecurity.ru\"",
                    "xmlns=\"http://tempuri.org/\""
            );
        }

        return baseRequest;
    }
}