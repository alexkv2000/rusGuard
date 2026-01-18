package kvo.rusguard.client;

import com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid;
import com.rusguard.client.*;
import com.rusguard.client.ILNetworkConfigurationService;
import com.rusguard.client.ILNetworkConfigurationServiceAddAcsEmployeeGroupArgumentExceptionFaultFaultMessage;
import com.rusguard.client.ILNetworkConfigurationServiceAddAcsEmployeeGroupArgumentOutOfRangeExceptionFaultFaultMessage;
import com.rusguard.client.ILNetworkConfigurationServiceAddAcsEmployeeGroupDataNotFoundExceptionFaultFaultMessage;
import com.rusguard.client.ILNetworkService;
import com.sun.xml.txw2.output.CharacterEscapeHandler;
import jakarta.xml.bind.JAXBElement;

import jakarta.xml.soap.*;
import jakarta.xml.ws.handler.MessageContext;
import jakarta.xml.ws.handler.soap.SOAPHandler;
import jakarta.xml.ws.handler.soap.SOAPMessageContext;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.LDriverFullInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.LNetInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.LServerInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.SortOrder;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity.*;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.*;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs_accesslevels.AcsAccessPointDriverInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs_accesslevels.ArrayOfAcsAccessPointDriverInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_net_services.DeviceCallMethodOperation;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.ArrayOfLNetInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.ArrayOfLServerInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.ArrayOfLDriverFullInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity.LogMsgType;

import javax.net.ssl.*;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.GregorianCalendar;
import javax.xml.datatype.DatatypeConfigurationException;

import javax.xml.namespace.QName;

import jakarta.xml.ws.BindingProvider;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.tempuri.LNetworkService;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import java.net.URL;
import java.util.*;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.transport.http.HTTPConduit;

import java.util.logging.Level;
import java.util.logging.Logger;

public class RusGuardAcsIntegrationSample {

    private static SSLContext createTrustAllSslContext() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            return sc;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void disableSSLVerification() {
        try {
            SSLContext sc = createTrustAllSslContext();
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = (hostname, session) -> true;

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void configureCxfTls(Object port) {
        org.apache.cxf.endpoint.Client client = org.apache.cxf.frontend.ClientProxy.getClient(port);
        if (!(client.getConduit() instanceof HTTPConduit)) {
            return;
        }

        HTTPConduit conduit = (HTTPConduit) client.getConduit();

        TLSClientParameters tlsParams = new TLSClientParameters();
        tlsParams.setDisableCNCheck(true);

        SSLContext sc = createTrustAllSslContext();
        tlsParams.setSSLSocketFactory(sc.getSocketFactory());

        conduit.setTlsClientParameters(tlsParams);
    }
//    private static final String SERVICE_URL = "https://10.0.0.25/LNetworkServer/LNetworkService.svc";
    private static final String SERVICE_URL = "https://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";
    private static final String USERNAME = "KvochkinAY";
    private static final String PASSWORD = "%*5I1OO4rpE%";
// Статические прокси-объекты
    private static ILNetworkService networkService;
    private static ILNetworkConfigurationService networkCnfgService;
    static {
        try {
//            disableSslVerification(); // Только для теста!
            initServices();
        } catch (Exception e) {
            throw new RuntimeException("Не удалось инициализировать сервисы RusGuard", e);
        }
    }

    private static void configureWSSecurity(BindingProvider port) {
        // Set WS-Security properties
        Map<String, Object> requestContext = port.getRequestContext();

        // Username token profile
        Map<String, Object> props = new HashMap<>();
        props.put(WSHandlerConstants.ACTION, WSHandlerConstants.USERNAME_TOKEN);
        props.put(WSHandlerConstants.USER, USERNAME);
        props.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
        props.put(WSHandlerConstants.PW_CALLBACK_REF, new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];
                pc.setPassword(PASSWORD);
            }
        });

        // Set the properties in the request context
        requestContext.put(WSHandlerConstants.USERNAME_TOKEN, USERNAME);
        requestContext.put(WSHandlerConstants.PASSWORD_TYPE, PASSWORD);
        requestContext.put(WSHandlerConstants.ADD_USERNAMETOKEN_NONCE, "true");
        requestContext.put(WSHandlerConstants.ADD_USERNAMETOKEN_CREATED, "true");

        // Set the security properties
        requestContext.put(org.apache.cxf.ws.security.SecurityConstants.USERNAME, USERNAME);
        requestContext.put(org.apache.cxf.ws.security.SecurityConstants.PASSWORD, PASSWORD);
        requestContext.put(org.apache.cxf.ws.security.SecurityConstants.CALLBACK_HANDLER, new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];
                pc.setPassword(PASSWORD);
            }
        });

        // Add the security interceptor
        org.apache.cxf.endpoint.Client client = org.apache.cxf.frontend.ClientProxy.getClient(port);
        org.apache.cxf.endpoint.Endpoint cxfEndpoint = client.getEndpoint();

        Map<String, Object> outProps = new HashMap<>();
        outProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.USERNAME_TOKEN);
        outProps.put(WSHandlerConstants.USER, USERNAME);
        outProps.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
        outProps.put(WSHandlerConstants.PW_CALLBACK_REF, new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];
                pc.setPassword(PASSWORD);
            }
        });

        org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor wssOut =
                new org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor(outProps);
        cxfEndpoint.getOutInterceptors().add(wssOut);
    }

    private static SOAPHandler<SOAPMessageContext> createSecurityHeader() {
        return new SOAPHandler<SOAPMessageContext>() {
            @Override
            public Set<QName> getHeaders() {
                return Collections.singleton(new QName(
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                        "Security", "wsse"));
            }

            @Override
            public boolean handleMessage(SOAPMessageContext context) {
                try {
                    SOAPMessage msg = context.getMessage();
                    SOAPPart sp = msg.getSOAPPart();
                    SOAPEnvelope se = sp.getEnvelope();

                    // Create security header
                    SOAPHeader header = se.getHeader();
                    if (header == null) {
                        header = se.addHeader();
                    }

                    // Add security header with username token
                    SOAPElement security = header.addChildElement("Security", "wsse",
                            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                    SOAPElement usernameToken = security.addChildElement("UsernameToken", "wsse");
                    SOAPElement username = usernameToken.addChildElement("Username", "wsse");
                    username.addTextNode(USERNAME);
                    SOAPElement password = usernameToken.addChildElement("Password", "wsse");
                    password.setAttribute("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
                    password.addTextNode(PASSWORD);

                    msg.saveChanges();
                } catch (Exception e) {
                    throw new RuntimeException("Error adding security header", e);
                }
                return true;
            }

            @Override
            public boolean handleFault(SOAPMessageContext context) {
                return true;
            }

            @Override
            public void close(MessageContext context) {
            }
        };
    }

    private static void initServices() {
        try {
            // Disable SSL verification (for development only)
            disableSSLVerification();

            Logger.getLogger("org.tempuri").setLevel(Level.OFF);
            Logger.getLogger("org.tempuri.LNetworkService").setLevel(Level.OFF);

            System.out.println("Инициализация сервисов...");
            System.out.println("Подключаемся к WSDL: " + SERVICE_URL + "?wsdl");

            // Create service
            LNetworkService service = new LNetworkService(new URL(SERVICE_URL + "?wsdl"));
            networkService = service.getBasicHttpBindingILNetworkService();

            configureCxfTls(networkService);

            // Configure WS-Security
            BindingProvider bp = (BindingProvider) networkService;
            configureWSSecurity(bp);

            System.out.println("Сервис успешно инициализирован");
        } catch (Exception e) {
            throw new RuntimeException("Не удалось инициализировать сервисы", e);
        }
    }
//    private static void disableSslVerification() throws NoSuchAlgorithmException, KeyManagementException {
//

    /// / Создаем доверяющий всем сертификатам TrustManager
//
//        TrustManager[] trustAllCerts = new TrustManager[]{
//
//                new X509TrustManager() {
//
//                    public X509Certificate[] getAcceptedIssuers() {
//                        return new X509Certificate[0];
//                    }
//
//                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
//                    }
//
//                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
//                    }
//
//                }
//
//        };
//
//
//        SSLContext sc = SSLContext.getInstance("SSL");
//
//        sc.init(null, trustAllCerts, new SecureRandom());
//
//        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
//
//        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
//
//    }
//    private static void initServices() {
//        try {
//            // 1. Отключаем проверку SSL (должно быть первым!)
//            disableSSLVerification();
//
//            // 2. Настройки для отладки
//            System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", "true");
//            System.setProperty("com.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump", "true");
//            System.setProperty("com.sun.xml.ws.transport.http.HttpAdapter.dump", "true");
//            System.setProperty("com.sun.xml.internal.ws.transport.http.HttpAdapter.dump", "true");
//            System.setProperty("javax.net.debug", "ssl,handshake");
//
//            // Отключаем проверку политики
//            System.setProperty("org.apache.cxf.stax.allowInsecureParser", "true");
//            System.setProperty("org.apache.cxf.stax.allowInsecureParser", "1");
//
//            System.out.println("Инициализация сервисов...");
//
//            // 3. Создаем URL к WSDL
//            String wsdlUrl = SERVICE_URL + "?wsdl";
//            System.out.println("Подключаемся к WSDL: " + wsdlUrl);
//
//            URL wsdlURL = new URL(wsdlUrl);
//            QName serviceName = new QName("http://tempuri.org/", "LNetworkService");
//
//            // 4. Создаем экземпляр сервиса
//            System.out.println("Создаем сервис...");
//            Service service = Service.create(wsdlURL, serviceName);
//            System.out.println("Сервис создан: " + (service != null));
//
//            // 5. Инициализируем сервис сети
//            System.out.println("Получаем порт ILNetworkService...");
//            networkService = service.getPort(ILNetworkService.class);
//            System.out.println("Порт ILNetworkService получен: " + (networkService != null));
//
//            // 6. Настраиваем конечную точку
//            configureEndpoint((BindingProvider) networkService);
//            System.out.println("Конечная точка сконфигурирована");
//
//            // 7. Инициализируем сервис конфигурации сети
//            System.out.println("Получаем порт ILNetworkConfigurationService...");
//            networkCnfgService = service.getPort(ILNetworkConfigurationService.class);
//            System.out.println("Порт ILNetworkConfigurationService получен: " + (networkCnfgService != null));
//
//            configureEndpoint((BindingProvider) networkCnfgService);
//
//            System.out.println("Сервисы успешно инициализированы");
//
//        } catch (Exception e) {
//            System.err.println("ОШИБКА при инициализации сервисов:");
//            e.printStackTrace();
//            throw new RuntimeException("Не удалось инициализировать сервисы", e);
//        }
//    }

    private static void configureEndpoint(BindingProvider port) {
        try {
            Map<String, Object> requestContext = port.getRequestContext();

            // Устанавливаем URL сервиса
            requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, SERVICE_URL);
            System.out.println("URL сервиса: " + SERVICE_URL);

            // Отключаем проверку политик WS-Security
            requestContext.put("ws-security.disable.wsm4j", "true");
            requestContext.put("ws-security.validate.token", "false");

            // Отключаем проверку политик безопасности
            requestContext.put("ws-security.enable.nonce.cache", "false");
            requestContext.put("ws-security.enable.timestamp.cache", "false");
            requestContext.put("ws-security.is-bsp-compliant", "false");

            // Отключаем проверку SSL
            System.setProperty("org.apache.cxf.stax.allowInsecureParser", "true");

            // Настройки безопасности (если нужны)
//            Map<String, Object> props = new HashMap<>();
//            props.put(SecurityConstants.USERNAME, USERNAME);
//            props.put(SecurityConstants.PASSWORD, "***"); // Не логируем пароль
//            props.put(SecurityConstants.CALLBACK_HANDLER, new ClientPasswordCallback(USERNAME, PASSWORD));
//
//            requestContext.put(SecurityConstants.class.getName() + ".security.properties", props);

            System.out.println("Настройки безопасности применены");

        } catch (Exception e) {
            System.err.println("Ошибка настройки конечной точки:");
            e.printStackTrace();
        }
    }


    private static void setCredentials(Object port) {
        BindingProvider bp = (BindingProvider) port;

        // Set endpoint address
        bp.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, SERVICE_URL);

        // Configure WS-Security UsernameToken
        Map<String, Object> requestContext = bp.getRequestContext();

        // Setup security headers
//        Map<String, Object> outProps = new HashMap<>();
//
//        // UsernameToken configuration
//        outProps.put("ws-security.username", USERNAME);
//        outProps.put("ws-security.password", PASSWORD);
//        outProps.put("ws-security.callback-handler", new ClientPasswordCallback(USERNAME, PASSWORD));

        // Use UsernameToken with password digest
//        outProps.put("ws-security.encryption.username", "useReqSigCert");
//        outProps.put("ws-security.signature.username", "useReqSigCert");
//        outProps.put("ws-security.encryption.properties", "clientKeystore.properties");
//        outProps.put("ws-security.signature.properties", "clientKeystore.properties");
//        outProps.put("ws-security.asymmetric.signature.algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
//
//        // Add the properties to the request context
//        requestContext.put("ws-security.sts.client", null);
//        requestContext.put("ws-security.signature.properties", "clientKeystore.properties");
//        requestContext.put("ws-security.encryption.properties", "clientKeystore.properties");
//        requestContext.put("ws-security.callback-handler", new ClientPasswordCallback(USERNAME, PASSWORD));
//        requestContext.put("ws-security.signature.username", "useReqSigCert");
//        requestContext.put("ws-security.encryption.username", "useReqSigCert");
//        requestContext.put("ws-security.asymmetric.signature.algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        // Enable streaming for better performance with large messages
        requestContext.put("jaxb.characterEscapeHandler", new NoEscapeHandler());

        // Set timeouts
        requestContext.put("javax.xml.ws.client.connectionTimeout", "10000");
        requestContext.put("javax.xml.ws.client.receiveTimeout", "10000");
    }

    // Inner class for password callback
    private static class ClientPasswordCallback implements CallbackHandler {
        private String username;
        private String password;

        public ClientPasswordCallback(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof WSPasswordCallback) {
                    WSPasswordCallback pc = (WSPasswordCallback) callback;
                    if (pc.getIdentifier().equals(username)) {
                        pc.setPassword(password);
                        return;
                    }
                }
            }
        }
    }

    // Simple NoEscapeHandler to prevent XML escaping
    private static class NoEscapeHandler implements CharacterEscapeHandler {
        @Override
        public void escape(char[] ch, int start, int length, boolean isAttVal, Writer out) throws IOException {
            out.write(ch, start, length);
        }
    }


// ================================

// #region Получить уровни доступа

// ================================


    public static AcsAccessLevelSlimInfo[] getAcsAccessLevels() {

        try {
// Получаем объект-обертку
            ArrayOfAcsAccessLevelSlimInfo result = networkService.getAcsAccessLevelsSlimInfo();
            // Извлекаем массив из объекта-обертки
            AcsAccessLevelSlimInfo[] levels = result.getAcsAccessLevelSlimInfo().toArray(new AcsAccessLevelSlimInfo[0]);

            // Фильтруем удаленные уровни
            List<AcsAccessLevelSlimInfo> active = new ArrayList<>();
            for (AcsAccessLevelSlimInfo level : levels) {
                if (level != null && !level.isIsRemoved()) {
                    active.add(level);
                }
            }
            return active.toArray(new AcsAccessLevelSlimInfo[0]);

        } catch (Exception e) {
            System.err.println("Ошибка получения уровней доступа: " + e.getMessage());
            return new AcsAccessLevelSlimInfo[0];
        }
    }


// ================================

// #region Работа с группами сотрудников

// ================================


    public static AcsEmployeeGroup[] getAcsEmployeeGroups() {
        try {
            // Get the ArrayOfAcsEmployeeGroup object
            ArrayOfAcsEmployeeGroup groupsWrapper = networkService.getAcsEmployeeGroups();

            // Convert it to an array of AcsEmployeeGroup
            List<AcsEmployeeGroup> groups = groupsWrapper.getAcsEmployeeGroup(); // or whatever the getter method is named

            List<AcsEmployeeGroup> active = new ArrayList<>();
            for (AcsEmployeeGroup group : groups) {
                if (!group.isIsRemoved()) {
                    active.add(group);
                }
            }

            return active.toArray(new AcsEmployeeGroup[0]);
        } catch (Exception e) {
            e.printStackTrace();
            return new AcsEmployeeGroup[0];
        }
    }


    public static AcsEmployeeGroup getGuestEmployeeGroup() {
        try {
            AcsEmployeeGroup[] groups = networkService.getAcsEmployeeGroups().getAcsEmployeeGroup().toArray(new AcsEmployeeGroup[0]);

            return Arrays.stream(groups)
                    .filter(g -> !g.isIsRemoved() && "Посетители".equals(g.getName()))
                    .findFirst()
                    .orElseGet(() -> {
                        // Создаём группу "Посетители", если не нашли существующую
                        try {
                            return networkCnfgService.addAcsEmployeeGroup(null, "Посетители", "", null, true, "");
                        } catch (ILNetworkConfigurationServiceAddAcsEmployeeGroupArgumentExceptionFaultFaultMessage e) {
                            throw new RuntimeException(e);
                        } catch (
                                ILNetworkConfigurationServiceAddAcsEmployeeGroupDataNotFoundExceptionFaultFaultMessage e) {
                            throw new RuntimeException(e);
                        } catch (
                                ILNetworkConfigurationServiceAddAcsEmployeeGroupArgumentOutOfRangeExceptionFaultFaultMessage e) {
                            throw new RuntimeException(e);
                        }
                    });

        } catch (Exception e) {
            System.err.println("Ошибка получения/создания группы посетителей: " + e.getMessage());
            return null;
        }
    }


    public static AcsEmployeeSlim[] getAcsEmployeesInGroup(String groupId) {
        try {
            // Get employees by group ID
//            AcsEmployeeSlim[] employees = networkService.getAcsEmployeesByGroup(String.valueOf(UUID.fromString(groupId)),false);
            ArrayOfAcsEmployeeSlim result = networkService.getAcsEmployeesByGroup(String.valueOf(UUID.fromString(groupId)), false);
            AcsEmployeeSlim[] employees = result.getAcsEmployeeSlim().toArray(new AcsEmployeeSlim[0]);
            // Filter out removed employees
            List<AcsEmployeeSlim> active = new ArrayList<>();
            for (AcsEmployeeSlim emp : employees) {
                if (!emp.isIsRemoved()) {
                    active.add(emp);
                }
            }

            // Convert list back to array
            return active.toArray(new AcsEmployeeSlim[0]);

        } catch (Exception e) {
            System.err.println("Error getting employees in group: " + e.getMessage());
            return new AcsEmployeeSlim[0]; // Return empty array in case of error
        }
    }


    public static AcsEmployeeFull getAcsEmployee(String id) {

        try {

            return networkService.getAcsEmployee(String.valueOf(UUID.fromString(id)));

        } catch (Exception e) {

            System.err.println("Ошибка получения полных данных сотрудника: " + e.getMessage());

            return null;

        }

    }


    public static AcsEmployeeSlim addAcsEmployee(String employeeGroupID, AcsEmployeeSaveData data) {

        try {

            return networkCnfgService.addAcsEmployee(String.valueOf(UUID.fromString(employeeGroupID)), data);

        } catch (Exception e) {

            System.err.println("Ошибка добавления сотрудника: " + e.getMessage());

            throw new RuntimeException(e);

        }

    }


    public static void saveAcsEmployee(String id, AcsEmployeeSaveData data) {

        try {

            networkCnfgService.saveAcsEmployee(String.valueOf(UUID.fromString(id)), data);

        } catch (Exception e) {

            System.err.println("Ошибка сохранения сотрудника: " + e.getMessage());

            throw new RuntimeException(e);

        }

    }


    public static void removeAcsEmployee(String id) {

        try {

            networkCnfgService.removeAcsEmployee(String.valueOf(UUID.fromString(id)));

        } catch (Exception e) {

            System.err.println("Ошибка удаления сотрудника: " + e.getMessage());

            throw new RuntimeException(e);

        }

    }


    public static void setAcsEmployeePhoto(String employeeId, int photoNumber, byte[] data) {

        try {

            networkCnfgService.setAcsEmployeePhoto(String.valueOf(UUID.fromString(employeeId)), photoNumber, data, true);

        } catch (Exception e) {

            System.err.println("Ошибка установки фото: " + e.getMessage());

            throw new RuntimeException(e);

        }

    }


    public static void addAccessLevelsToEmployee(String employeeID, String[] accessLevelIDs) {

        try {
            // Convert String[] to ArrayOfguid
            ArrayOfguid arrayOfGuid = new ArrayOfguid();
            arrayOfGuid.getGuid().addAll(Arrays.asList(accessLevelIDs));

            // Call with correct parameter types
            networkCnfgService.addAccessLevelsToEmployee(employeeID, arrayOfGuid);
        } catch (Exception e) {
            System.err.println("Ошибка назначения уровней доступа: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


    public static void removeAccessLevelFromEmployee(String employeeID, String[] accessLevelIDs) {

        try {
            // Create ArrayOfguid object
            ArrayOfguid arrayOfGuid = new ArrayOfguid();
            arrayOfGuid.getGuid().addAll(Arrays.asList(accessLevelIDs));

            // Call the service with correct parameter types
            networkCnfgService.removeAccessLevelFromEmployee(employeeID, arrayOfGuid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void setUseEmployeeParentAccessLevel(String employeeID, boolean isUseParentAccessLevel) {
        try {
            networkCnfgService.setUseEmployeeParentAccessLevel(
                    employeeID, // employeeID as String
                    isUseParentAccessLevel, // isUseParentAccessLevel as boolean
                    false // partOfCreateOperation set to false by default
            );
        } catch (Exception e) {
            System.err.println("Ошибка установки флага IsAccessLevelsInherited: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


// ================================

// #region Блокировка сотрудников

// ================================


    public static void lockAcsEmployee(String[] ids, boolean isLocked) {
        try {
            // Create ArrayOfguid and add all UUIDs to it
            ArrayOfguid arrayOfGuid = new ArrayOfguid();
            for (String id : ids) {
                arrayOfGuid.getGuid().add(String.valueOf(UUID.fromString(id)));
            }

            // Call the service with correct parameter types
            networkCnfgService.lockAcsEmployee(arrayOfGuid, isLocked);
        } catch (Exception e) {
            System.err.println("Ошибка блокировки сотрудников: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


// ================================

// #region Работа с ключами

// ================================


    public static void removeKeyFromEmployee(String employeeId, int indexNumber) {
        try {
            networkCnfgService.assignAcsKeyForEmployee(employeeId, indexNumber, null, false);
        } catch (Exception e) {
            System.err.println("Ошибка снятия ключа: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


    public static AcsKeyInfo assignAcsKeyForEmployee(String employeeId, int indexNumber, AcsKeySaveData keyData) {
        try {
            return networkCnfgService.assignAcsKeyForEmployee(employeeId, indexNumber, keyData, false);
        } catch (Exception e) {
            System.err.println("Ошибка назначения ключа: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static AcsKeyInfo forceAssignAcsKeyForEmployee(String employeeId, int indexNumber, AcsKeySaveData keyData) {
        try {
            return networkCnfgService.forceAssignAcsKeyForEmployee(employeeId, indexNumber, keyData, false);
        } catch (Exception e) {
            System.err.println("Ошибка принудительного назначения ключа: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

// ================================

// #region Работа с событиями

// ================================


    public static void trackEvents(String[] accessPointsIds) throws DatatypeConfigurationException {
        // Use LogMsgType instead of LogMsgSubType
        LogMsgType[] filter = {
                LogMsgType.ALARM,
                LogMsgType.WARNING,
                LogMsgType.INFORMATION
        };

        long counter = -1;

        while (counter == -1) {
            // Pass null for subTypes parameter since we can't use LogMsgSubType
            LogData lastEvent = networkService.getLastEvent(null, null, toUuidArray(accessPointsIds), LogSubjectType.NONE);

            if (lastEvent != null && lastEvent.getMessages() != null && !lastEvent.getMessages().isNil()) {
                ArrayOfLogMessage messages = lastEvent.getMessages().getValue();
                counter = messages.getLogMessage().stream()
                        .mapToLong(LogMessage::getId)
                        .max()
                        .orElse(-1);
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }

        while (true) {
            // First, convert the filter array to ArrayOfLogMsgSubType
            ArrayOfLogMsgSubType msgSubTypes = new ArrayOfLogMsgSubType();
            for (LogMsgType subType : filter) {
                msgSubTypes.getLogMsgSubType().add(String.valueOf(subType));
            }

// Convert Date to XMLGregorianCalendar
            XMLGregorianCalendar startDate = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(new GregorianCalendar(1970, 0, 1)); // Equivalent to new Date(0)
            XMLGregorianCalendar endDate = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(new GregorianCalendar(292278994, 7, 17)); // Far future date

            LogData events = networkService.getEvents(
                    counter, // fromMessageId
                    startDate, // fromDateTime
                    endDate, // toDateTime
                    null, // msgTypes (ArrayOfLogMsgType)
                    msgSubTypes, // msgSubTypes (ArrayOfLogMsgSubType)
                    toUuidArray(accessPointsIds), // subjectIDs (ArrayOfguid)
                    LogSubjectType.NONE, // subjectType
                    0, // pageNumber
                    1000, // pageSize
                    LogMessageSortedColumn.DATE_TIME, // sortedColumn
                    SortOrder.ASCENDING // sortOrder
            );
            if (events != null && events.getMessages() != null) {
                for (LogMessage msg : events.getMessages().getValue().getLogMessage()) {
                    System.out.println("Event: " + msg.getMessage() +
                            " at " + msg.getDateTime() +
                            " type: " + msg.getLogMessageType());
                }

                ArrayOfLogMessage messages = events.getMessages().getValue();
                if (messages != null && messages.getLogMessage() != null && !messages.getLogMessage().isEmpty()) {
                    List<LogMessage> messageList = messages.getLogMessage();
                    counter = messageList.get(messageList.size() - 1).getId() + 1;
                }
            }

            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }


    public static LogData getEvents(String[] accessPointsIds) throws DatatypeConfigurationException {
        // Convert dates to XMLGregorianCalendar
        DatatypeFactory df = DatatypeFactory.newInstance();
        XMLGregorianCalendar beginDate = df.newXMLGregorianCalendar(new GregorianCalendar(2012, Calendar.JANUARY, 1));
        XMLGregorianCalendar endDate = df.newXMLGregorianCalendar(new GregorianCalendar(2012, Calendar.JANUARY, 31, 23, 59, 59));

        // Create ArrayOfLogMsgType for message types
        ArrayOfLogMsgType msgTypes = new ArrayOfLogMsgType();
        // Create ArrayOfLogMsgSubType for message sub-types
        ArrayOfLogMsgSubType msgSubTypes = new ArrayOfLogMsgSubType();

        // Convert access point IDs to ArrayOfguid
        ArrayOfguid deviceIDs = new ArrayOfguid();
        if (accessPointsIds != null) {
            for (String id : accessPointsIds) {
                deviceIDs.getGuid().add(id);
            }
        }

        return networkService.getEventsByDeviceIDs(
                0L,                              // fromMessageId
                beginDate,                       // fromDateTime
                endDate,                         // toDateTime
                null,                            // msgTypes (ArrayOfLogMsgType)
                msgSubTypes,                     // msgSubTypes (ArrayOfLogMsgSubType)
                deviceIDs,                       // deviceIDs (ArrayOfguid)
                null,                            // subjectIDs (ArrayOfguid)
                LogSubjectType.NONE,             // subjectType
                0,                               // pageNumber
                1000,                            // pageSize
                LogMessageSortedColumn.DATE_TIME, // sortedColumn
                SortOrder.ASCENDING              // sortOrder
        );
    }

    public static AcsAccessPointDriverInfo[] getAccessPoints() {
        try {
            ArrayOfAcsAccessPointDriverInfo result = networkService.getAcsAccessPointDrivers();
            return result.getAcsAccessPointDriverInfo().toArray(new AcsAccessPointDriverInfo[0]);
        } catch (Exception e) {
            System.err.println("Ошибка получения точек доступа: " + e.getMessage());
            return new AcsAccessPointDriverInfo[0];
        }
    }

    // ================================
// #region Получение драйверов и отправка команд
// ================================
    public static List<LDriverFullInfo> getAllDrivers() {
        try {
            List<LDriverFullInfo> result = new ArrayList<>();
            ArrayOfLNetInfo networks = networkService.getAllNets();

            for (LNetInfo net : networks.getLNetInfo()) {
                ArrayOfLServerInfo servers = networkService.getNetServers(net.getId().toString());

                for (LServerInfo server : servers.getLServerInfo()) {
                    ArrayOfLDriverFullInfo drivers = networkService.getServerDriversFullInfo(
                            server.getId().toString(),
                            null  // workplaceModuleId может быть null, если не требуется
                    );
                    result.addAll(drivers.getLDriverFullInfo());
                }
            }
            return result;
        } catch (Exception e) {
            System.err.println("Ошибка получения всех драйверов: " + e.getMessage());
            e.printStackTrace();  // Добавим вывод стека для отладки
            return new ArrayList<>();
        }
    }

    public static AcsAccessPointDriverInfo[] getAccessPointsDrivers2() {
        return getAccessPoints();
    }

    public static void sendCommand(String connectionId, String driverId, String commandName) {
        try {
            DeviceCallMethodOperation operation = new DeviceCallMethodOperation();

            // Set the method name (command)
            operation.setMethodName(new JAXBElement<>(
                    new QName("http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.Net.Services.Entities", "MethodName"),
                    String.class,
                    commandName
            ));

            // Process the operation
            networkService.process(operation, connectionId);
        } catch (Exception e) {
            System.err.println("Ошибка отправки команды: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    // Вспомогательный метод: преобразование String[] в UUID[]
    private static ArrayOfguid toUuidArray(String[] ids) {
        if (ids == null) return null;
        ArrayOfguid result = new ArrayOfguid();
        for (String id : ids) {
            if (id != null) {
                result.getGuid().add(UUID.fromString(id).toString());
            }
        }
        return result;
    }

// ================================
// #region Пример использования
//    ID: 6d353b9b-352e-442f-ae24-70791992c1a3, GroupID: , LastName: Квочкин, FirstName: Алексей, SecondName: Юрьевич
//    ID: eb1eb9e9-da50-412b-867b-9008bb3af985, GroupID: , LastName: Мергазымова, FirstName: Ольга, SecondName: Владимировна
//    ID: c675452f-6881-426d-99a7-d7af2fc6b943, GroupID: , LastName: Торопов, FirstName: Михаил, SecondName: Викторович
//    ID: e4f9bf7f-3bc0-4278-9e18-19693d1d92fb, GroupID: , LastName: Жирнов, FirstName: Сергей, SecondName: Алексеевич
//    ID: cc4990aa-b309-479e-a484-65e4abe80dfe, GroupID: , LastName: Кокурин, FirstName: Максим, SecondName: Романович
//    ID: 4bf9f60a-da45-4646-b6cd-f8b0bdbaad75, GroupID: , LastName: Ермолаев, FirstName: Алексей, SecondName: Сергеевич
// ================================

    public static void main(String[] args) {
        try {
            Logger.getLogger("org.tempuri").setLevel(Level.OFF);
            Logger.getLogger("org.tempuri.LNetworkService").setLevel(Level.OFF);

            // Добавляем системные свойства для отключения проверки политики
            System.setProperty("org.apache.cxf.stax.allowInsecureParser", "true");
            System.setProperty("ws-security.disable.wsm4j", "true");
            System.setProperty("ws-security.validate.token", "false");

            System.out.println("=== RusGuard ACS Java Integration Sample ===");
            System.out.println("Classpath: " + System.getProperty("java.class.path"));

            // Инициализация сервисов
            initServices();

//            getEmployee(); //ID: 620da80a-c0fd-4a4a-ab5a-3518a4615c1d, GroupID: , LastName: КОМАРОВ, FirstName: ОЛЕГ, SecondName: ДМИТРИЕВИЧ
            getAllEmployees();

        } catch (Exception e) {
            System.err.println("Ошибка при выполнении поиска: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void getEmployee() {
        // Создаем условие поиска
        SearchCondition searchCondition = new SearchCondition();

        // Устанавливаем фамилию для поиска
        JAXBElement<String> lastNameElement = new JAXBElement<>(
                new QName("http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS", "LastName"),
                String.class,
                "Квочкин"
        );
        searchCondition.setLastName(lastNameElement);

        // Создаем элемент условия поиска
        QName searchConditionQName = new QName("http://tempuri.org/", "SearchCondition");
        JAXBElement<SearchCondition> searchConditionElement = new JAXBElement<>(
                searchConditionQName,
                SearchCondition.class,
                searchCondition
        );

        // Создаем запрос на поиск
        FindEmployees findEmployees = new FindEmployees();
        findEmployees.setSearchCondition(searchConditionElement);
        // Выполняем поиск
        System.out.println("Выполнение поиска сотрудников...");
        ArrayOfAcsEmployee result = networkService.findEmployees(searchCondition);

        // Обрабатываем результаты
        if (result != null && result.getAcsEmployee() != null) {
            System.out.println("Найдено сотрудников: " + result.getAcsEmployee().size());
            for (AcsEmployee employee : result.getAcsEmployee()) {
                System.out.println("ID: " + employee.getEmployeeID());
            }
        } else {
            System.out.println("Сотрудники не найдены");
        }
    }

    private static void getAllEmployees() {
        SearchCondition searchCondition = new SearchCondition();
        searchCondition.setIsGlobalSearch(true);
        searchCondition.setIncludeRemoved(true);

        System.out.println("Выполнение поиска всех сотрудников...");
        ArrayOfAcsEmployee result = networkService.findEmployees(searchCondition);

        if (result != null && result.getAcsEmployee() != null && !result.getAcsEmployee().isEmpty()) {
            System.out.println("Найдено сотрудников: " + result.getAcsEmployee().size());
            for (AcsEmployee employee : result.getAcsEmployee()) {
                System.out.println(
                        "ID: " + getValue(employee, "getEmployeeID") +
                                ", GroupID: " + getValue(employee, "getGroupID") +
                                ", LastName: " + getValue(employee, "getLastName") +
                                ", FirstName: " + getValue(employee, "getFirstName") +
                                ", SecondName: " + getValue(employee, "getSecondName")
                );
            }
            return;
        }

        System.out.println("findEmployees вернул 0, получаем сотрудников через группы...");

        ArrayOfAcsEmployeeGroup groupsWrapper = networkService.getAcsEmployeeGroups();
        if (groupsWrapper == null || groupsWrapper.getAcsEmployeeGroup() == null) {
            System.out.println("Не удалось получить группы сотрудников");
            return;
        }

        java.util.Set<String> seenEmployeeIds = new java.util.HashSet<>();
        java.util.Set<String> visitedGroupIds = new java.util.HashSet<>();
        int total = collectEmployeesFromGroupsRecursive(groupsWrapper.getAcsEmployeeGroup(), visitedGroupIds, seenEmployeeIds);
        System.out.println("Итого сотрудников (через группы): " + total);
    }

    private static int collectEmployeesFromGroupsRecursive(
            java.util.List<AcsEmployeeGroup> groups,
            java.util.Set<String> visitedGroupIds,
            java.util.Set<String> seenEmployeeIds
    ) {
        if (groups == null || groups.isEmpty()) {
            return 0;
        }

        int total = 0;

        for (AcsEmployeeGroup group : groups) {
            if (group == null) {
                continue;
            }

            String groupId = group.getID();
            if (groupId == null || groupId.isEmpty() || !visitedGroupIds.add(groupId)) {
                continue;
            }

            ArrayOfAcsEmployeeSlim employeesWrapper;
            try {
                employeesWrapper = networkService.getAcsEmployeesByGroup(groupId, true);
            } catch (ILNetworkServiceGetAcsEmployeesByGroupDataNotFoundExceptionFaultFaultMessage e) {
                employeesWrapper = null;
            }

            if (employeesWrapper != null && employeesWrapper.getAcsEmployeeSlim() != null) {
                for (AcsEmployeeSlim emp : employeesWrapper.getAcsEmployeeSlim()) {
                    if (emp == null) {
                        continue;
                    }
                    String id = String.valueOf(getValue(emp, "getID"));
                    if (id.isEmpty() || !seenEmployeeIds.add(id)) {
                        continue;
                    }
                    total++;
                    System.out.println(
                            "ID: " + id +
                                    ", GroupID: " + getValue(emp, "getGroupID") +
                                    ", LastName: " + getValue(emp, "getLastName") +
                                    ", FirstName: " + getValue(emp, "getFirstName") +
                                    ", SecondName: " + getValue(emp, "getSecondName")
                    );
                }
            }

            // Рекурсивно обходим вложенные группы
            if (group.getEmployeeGroups() != null && group.getEmployeeGroups().getValue() != null) {
                total += collectEmployeesFromGroupsRecursive(
                        group.getEmployeeGroups().getValue().getAcsEmployeeGroup(),
                        visitedGroupIds,
                        seenEmployeeIds
                );
            }
        }

        return total;
    }

    private static Object getValue(Object obj, String methodName) {
        try {
            java.lang.reflect.Method m = obj.getClass().getMethod(methodName);
            Object v = m.invoke(obj);
            if (v == null) {
                return "";
            }
            if (v instanceof JAXBElement) {
                return ((JAXBElement<?>) v).getValue();
            }
            return v;
        } catch (Exception e) {
            return "";
        }
    }
}
