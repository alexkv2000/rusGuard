package com.rusguard.client;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.headers.Header;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.ArrayOfAcsEmployee;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.SearchCondition;

import javax.xml.namespace.QName;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class ManualSoapClient {

    public static void main(String[] args) {
        try {
            System.out.println("=== РУЧНОЙ SOAP КЛИЕНТ ===");

            URL wsdlUrl = ManualSoapClient.class.getClassLoader()
                    .getResource("wsdl/LNetworkServer/LNetworkService.wsdl");

            if (wsdlUrl == null) {
                System.err.println("ERROR: WSDL не найден!");
                return;
            }

            // 1. Создаем фабрику
            JaxWsProxyFactoryBean factory = new JaxWsProxyFactoryBean();
            factory.setWsdlURL(wsdlUrl.toString());
            factory.setServiceClass(ILNetworkService.class);
            factory.setServiceName(new QName("http://tempuri.org/", "LNetworkService"));
            factory.setEndpointName(new QName("http://tempuri.org/", "BasicHttpBinding_ILNetworkService"));
            factory.setAddress("http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc");

            // 2. Создаем клиент
            ILNetworkService port = (ILNetworkService) factory.create();
            org.apache.cxf.endpoint.Client client = org.apache.cxf.frontend.ClientProxy.getClient(port);

            // 3. Добавляем интерсептор для РУЧНОГО создания SOAP сообщения
            client.getOutInterceptors().add(new AbstractPhaseInterceptor<SoapMessage>(Phase.PRE_STREAM) {
                @Override
                public void handleMessage(SoapMessage message) throws Fault {
                    try {
                        // Получаем выходной поток
                        java.io.OutputStream os = message.getContent(java.io.OutputStream.class);

                        // Создаем SOAP сообщение вручную
                        String soapRequest = createManualSoapRequest();

                        System.out.println("\n=== РУЧНОЙ SOAP ЗАПРОС ===");
                        System.out.println(soapRequest);
                        System.out.println("=== КОНЕЦ ЗАПРОСА ===\n");

                        // Пишем в поток
                        os.write(soapRequest.getBytes("UTF-8"));
                        os.flush();

                        // Отменяем стандартную обработку
                        message.setContent(java.io.OutputStream.class, null);

                    } catch (Exception e) {
                        throw new Fault(e);
                    }
                }
            });

            // 4. Настраиваем аутентификацию
            java.util.Map<String, Object> requestContext = client.getRequestContext();
            requestContext.put("ws-security.username", "KvochkinAY");
            requestContext.put("ws-security.password", "%*5I1OO4rpE%");

            // Добавляем Basic Auth в заголовки
            java.util.Map<String, List<String>> headers = new java.util.HashMap<>();
            String auth = "KvochkinAY" + ":" + "%*5I1OO4rpE%";
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            headers.put("Authorization", java.util.Collections.singletonList("Basic " + encodedAuth));
            requestContext.put(Message.PROTOCOL_HEADERS, headers);

            // 5. Вызываем метод
            System.out.println("Вызываем findEmployees с ручным SOAP...");

            try {
                SearchCondition searchParams = new SearchCondition();
                ArrayOfAcsEmployee result = port.findEmployees(searchParams);

                System.out.println("✅ УСПЕХ!");
                if (result != null && result.getAcsEmployee() != null) {
                    System.out.println("Найдено: " + result.getAcsEmployee().size() + " сотрудников");
                }

            } catch (Exception e) {
                System.err.println("❌ Ошибка: " + e.getClass().getSimpleName());
                System.err.println("Сообщение: " + e.getMessage());

                // Получаем и показываем SOAP Fault если есть
                if (e.getCause() instanceof org.apache.cxf.binding.soap.SoapFault) {
                    org.apache.cxf.binding.soap.SoapFault fault = (org.apache.cxf.binding.soap.SoapFault) e.getCause();
                    System.err.println("\n=== SOAP FAULT ===");
                    System.err.println("Fault Code: " + fault.getFaultCode());
                    System.err.println("Fault String: " + fault.getFaultCode().toString());
                    System.err.println("Fault Detail: " + fault.getDetail());
                }
            }

        } catch (Exception e) {
            System.err.println("\n=== КРИТИЧЕСКАЯ ОШИБКА ===");
            e.printStackTrace();
        }
    }

    private static String createManualSoapRequest() {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\n" +
                "               xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                "               xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n" +
                "  <soap:Header>\n" +
                "    <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n" +
                "                   xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n" +
                "      <wsse:UsernameToken wsu:Id=\"UsernameToken-1\">\n" +
                "        <wsse:Username>KvochkinAY</wsse:Username>\n" +
                "        <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">%*5I1OO4rpE%</wsse:Password>\n" +
                "      </wsse:UsernameToken>\n" +
                "    </wsse:Security>\n" +
                "    <wsa:Action xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">\n" +
                "      http://www.rusguardsecurity.ru/ILDataService/FindEmployees\n" +
                "    </wsa:Action>\n" +
                "    <wsa:To xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">\n" +
                "      http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc\n" +
                "    </wsa:To>\n" +
                "  </soap:Header>\n" +
                "  <soap:Body>\n" +
                "    <FindEmployees xmlns=\"http://www.rusguardsecurity.ru\">\n" +
                "      <conditions>\n" +
                "        <!-- Пустые условия поиска -->\n" +
                "      </conditions>\n" +
                "    </FindEmployees>\n" +
                "  </soap:Body>\n" +
                "</soap:Envelope>";
    }
}