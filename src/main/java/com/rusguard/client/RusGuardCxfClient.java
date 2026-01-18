package com.rusguard.client;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.ws.addressing.WSAddressingFeature;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.ArrayOfAcsEmployee;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.SearchCondition;

import javax.xml.namespace.QName;
import java.net.URL;
import java.util.List;

public class RusGuardCxfClient {

    public static class FixActionInterceptor extends AbstractPhaseInterceptor<Message> {
        private final String correctAction;

        public FixActionInterceptor(String correctAction) {
            super(Phase.PRE_PROTOCOL);
            this.correctAction = correctAction;
        }

        @Override
        public void handleMessage(Message message) throws Fault {
            try {
                message.put("org.apache.cxf.binding.soap.action", correctAction);

                @SuppressWarnings("unchecked")
                java.util.Map<String, List<String>> httpHeaders =
                        (java.util.Map<String, List<String>>) message.get(Message.PROTOCOL_HEADERS);

                if (httpHeaders == null) {
                    httpHeaders = new java.util.HashMap<>();
                    message.put(Message.PROTOCOL_HEADERS, httpHeaders);
                }

                httpHeaders.put("SOAPAction", java.util.Collections.singletonList(correctAction));

                System.out.println("[Interceptor] Установлен SOAP Action: " + correctAction);

            } catch (Exception e) {
                System.err.println("[Interceptor] Ошибка: " + e.getMessage());
                throw new Fault(e);
            }
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("=== CXF КЛИЕНТ С ПРАВИЛЬНЫМ ПОРТОМ ===");

            // 1. Получаем WSDL
            URL wsdlUrl = RusGuardCxfClient.class.getClassLoader()
                    .getResource("wsdl/LNetworkServer/LNetworkService.wsdl");

            if (wsdlUrl == null) {
                System.err.println("ERROR: WSDL не найден!");
                return;
            }

            // 2. Определяем правильные QName из вашего WSDL
            // Откройте WSDL файл и найдите:
            // - service name
            // - port name

            // Обычно для WCF это:
            QName serviceName = new QName("http://tempuri.org/", "LNetworkService");
            QName portName = new QName("http://tempuri.org/", "BasicHttpBinding_ILNetworkService");

            // ИЛИ (попробуйте оба варианта):
//             QName serviceName = new QName("http://www.rusguardsecurity.ru", "LNetworkService");
//             QName portName = new QName("http://www.rusguardsecurity.ru", "BasicHttpBinding_ILNetworkService");

            System.out.println("Service QName: " + serviceName);
            System.out.println("Port QName: " + portName);

            // 3. Создаем фабрику с явным указанием порта
            JaxWsProxyFactoryBean factory = new JaxWsProxyFactoryBean();
            factory.setWsdlURL(wsdlUrl.toString());
            factory.setServiceClass(ILNetworkService.class);

            // Явно указываем service и port
            factory.setServiceName(serviceName);
            factory.setEndpointName(portName);

            // Endpoint
            String endpoint = "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";
            factory.setAddress(endpoint);

            // Добавляем WS-Addressing (важно для WCF!)
            factory.getFeatures().add(new WSAddressingFeature());

            // 4. Создаем клиент
            ILNetworkService port = (ILNetworkService) factory.create();
            System.out.println("✓ CXF клиент создан с правильным портом");

            // 5. Настраиваем интерсептор
            Client client = ClientProxy.getClient(port);
            String correctAction = "http://www.rusguardsecurity.ru/ILDataService/FindEmployees";
            client.getOutInterceptors().add(new FixActionInterceptor(correctAction));
            System.out.println("✓ Интерсептор добавлен");

            // 6. Настраиваем аутентификацию
            java.util.Map<String, Object> requestContext = client.getRequestContext();
            requestContext.put("ws-security.username", "KvochkinAY");
            requestContext.put("ws-security.password", "%*5I1OO4rpE%");

            // 7. Создаем запрос
            SearchCondition searchParams = new SearchCondition();

            // 8. Вызываем метод
            System.out.println("\nВызываем findEmployees...");

            try {
                ArrayOfAcsEmployee result = port.findEmployees(searchParams);

                System.out.println("\n✅ УСПЕХ!");
                if (result != null && result.getAcsEmployee() != null) {
                    System.out.println("Найдено: " + result.getAcsEmployee().size() + " сотрудников");
                }

            } catch (Exception e) {
                System.err.println("\n❌ ОШИБКА: " + e.getClass().getSimpleName());
                System.err.println("Сообщение: " + e.getMessage());

                // Дополнительная диагностика
                diagnoseProblem(e, serviceName, portName);
            }

        } catch (Exception e) {
            System.err.println("\n=== КРИТИЧЕСКАЯ ОШИБКА ===");
            e.printStackTrace();
        }
    }

    private static void diagnoseProblem(Exception e, QName serviceName, QName portName) {
        System.err.println("\n=== ДИАГНОСТИКА ===");
        System.err.println("Service: " + serviceName);
        System.err.println("Port: " + portName);
        System.err.println("Endpoint: http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc");
        System.err.println("Action: http://www.rusguardsecurity.ru/ILDataService/FindEmployees");

        System.err.println("\nПопробуйте:");
        System.err.println("1. Проверить правильность QName в WSDL");
        System.err.println("2. Использовать другой порт");
        System.err.println("3. Проверить доступность сервера");

        // Попробуйте найти правильные QName в WSDL
        System.err.println("\nКак найти правильные QName:");
        System.err.println("1. Откройте LNetworkService.wsdl");
        System.err.println("2. Найдите <wsdl:service name=\"...\">");
        System.err.println("3. Найдите <wsdl:port name=\"...\" binding=\"...\">");
    }
}