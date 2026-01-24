package kvo.rusguard.client;

import com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid;
import com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfint;
import com.rusguard.client.*;
import com.rusguard.client.ILNetworkConfigurationService;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;

import jakarta.xml.bind.JAXBElement;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.AcsEmployeeSaveData;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.AcsEmployeeSlim;
import com.rusguard.client.ILNetworkService;
import com.sun.xml.txw2.output.CharacterEscapeHandler;

import jakarta.xml.soap.*;
import jakarta.xml.ws.handler.MessageContext;
import jakarta.xml.ws.handler.soap.SOAPHandler;
import jakarta.xml.ws.handler.soap.SOAPMessageContext;
import jakarta.xml.ws.soap.SOAPFaultException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;


import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities.*;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.GregorianCalendar;


import jakarta.xml.ws.BindingProvider;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity.*;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.*;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs_accesslevels.AcsAccessPointDriverInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs_accesslevels.ArrayOfAcsAccessPointDriverInfo;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_net_services.DeviceCallMethodOperation;
import org.tempuri.LNetworkService;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import java.net.URL;
import java.util.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

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
import java.util.stream.Collectors;

public class RusGuardAcsIntegrationSample {

    private static final String NS_EMPLOYEES = "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees";

    private static SSLContext createTrustAllSslContext() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
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
        tlsParams.setSslContext(sc);
        tlsParams.setSSLSocketFactory(sc.getSocketFactory());
        tlsParams.setHostnameVerifier((hostname, session) -> true);

        conduit.setTlsClientParameters(tlsParams);
    }

    //    private static final String SERVICE_URL = "https://10.0.0.25/LNetworkServer/LNetworkService.svc";
    private static final String SERVICE_URL = "https://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";
    private static final String CONFIG_SERVICE_URL = SERVICE_URL;
    private static final String USERNAME = "KvochkinAY";
    private static final String PASSWORD = "%*5I1OO4rpE%";
    // Статические прокси-объекты
    private static ILNetworkService networkService;
    private static ILNetworkConfigurationService networkCnfgService;


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
            if (networkService != null && networkCnfgService != null) {
                return;
            }

            // Disable SSL verification (for development only)
            disableSSLVerification();
            //Подавление вывода Логов
            Logger.getLogger("org.tempuri").setLevel(Level.OFF);
            Logger.getLogger("org.tempuri.LNetworkService").setLevel(Level.OFF);

            System.out.println("Инициализация сервисов...");
            System.out.println("Подключаемся к WSDL: " + SERVICE_URL + "?wsdl");

            // Create service from classpath WSDL to avoid network WSDL download
            URL wsdlUrl = RusGuardAcsIntegrationSample.class.getClassLoader()
                    .getResource("wsdl/LNetworkServer/LNetworkService.wsdl");
            if (wsdlUrl == null) {
                throw new IllegalStateException("WSDL not found in classpath: wsdl/LNetworkServer/LNetworkService.wsdl");
            }

            LNetworkService service = new LNetworkService(wsdlUrl);
            if (networkService == null) {
                networkService = service.getBasicHttpBindingILNetworkService();
            }
            if (networkCnfgService == null) {
                networkCnfgService = service.getBasicHttpBindingILNetworkConfigurationService();
            }

            // Configure timeouts (milliseconds) + force URLConnectionHTTPConduit
            BindingProvider bpTimeout = (BindingProvider) networkService;
            bpTimeout.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, SERVICE_URL);
            bpTimeout.getRequestContext().put("force.urlconnection.http.conduit", Boolean.TRUE);
            bpTimeout.getRequestContext().put("javax.xml.ws.client.connectionTimeout", "10000");
            bpTimeout.getRequestContext().put("javax.xml.ws.client.receiveTimeout", "30000");
            bpTimeout.getRequestContext().put("jakarta.xml.ws.client.connectionTimeout", "10000");
            bpTimeout.getRequestContext().put("jakarta.xml.ws.client.receiveTimeout", "30000");

            BindingProvider bpTimeoutCfg = (BindingProvider) networkCnfgService;
            bpTimeoutCfg.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, CONFIG_SERVICE_URL);
            bpTimeoutCfg.getRequestContext().put("force.urlconnection.http.conduit", Boolean.TRUE);
            bpTimeoutCfg.getRequestContext().put("javax.xml.ws.client.connectionTimeout", "10000");
            bpTimeoutCfg.getRequestContext().put("javax.xml.ws.client.receiveTimeout", "30000");
            bpTimeoutCfg.getRequestContext().put("jakarta.xml.ws.client.connectionTimeout", "10000");
            bpTimeoutCfg.getRequestContext().put("jakarta.xml.ws.client.receiveTimeout", "30000");

            configureCxfTls(networkService);
            configureCxfTls(networkCnfgService);

            // Configure WS-Security
            configureWSSecurity((BindingProvider) networkService);
            configureWSSecurity((BindingProvider) networkCnfgService);

            System.out.println("Сервис успешно инициализирован");
        } catch (Exception e) {
            throw new RuntimeException("Не удалось инициализировать сервисы", e);
        }
    }

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


    public static AcsEmployeeFull getAcsEmployee(String id) { //Получить полные данные о сотруднике

        try {

            return networkService.getAcsEmployee(String.valueOf(UUID.fromString(id)));

        } catch (Exception e) {

            System.err.println("Ошибка получения полных данных сотрудника: " + e.getMessage());

            return null;

        }

    }


    public static AcsEmployeeSlim addAcsEmployee(String employeeGroupID, AcsEmployeeSaveData data) { // Добавление сотрудников в группу
        try {
            return networkCnfgService.addAcsEmployee(String.valueOf(UUID.fromString(employeeGroupID)), data);
        } catch (Exception e) {
            System.err.println("Ошибка добавления сотрудника: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


    public static void saveAcsEmployee(String id, AcsEmployeeSaveData data) { //Сохранить данные сотрудника
        try {
            networkCnfgService.saveAcsEmployee(String.valueOf(UUID.fromString(id)), data);
        } catch (Exception e) {
            System.err.println("Ошибка сохранения сотрудника: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static void removeAcsEmployee(String id) { //Удаление сотрудника
        try {
            networkCnfgService.removeAcsEmployee(String.valueOf(UUID.fromString(id)));
        } catch (Exception e) {
            System.err.println("Ошибка удаления сотрудника: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


    public static void setAcsEmployeePhoto(String employeeId, int photoNumber, byte[] data) { // Добавить фотографию сотруднику, удалить фотографию у сотрудника
        try {
            //photoNumber - параметр, указывающий номер(поизицию фотографии), нумерация начинается с еденицы.
            //В настройках сервисов есть ограничение на объем передаваемых данных в параметре data,
            //data не должно превышать 4 Mb
            //Для удаления фотографии с позицией, указанной в photoNumber, в параметре data следует указать null
            networkCnfgService.setAcsEmployeePhoto(String.valueOf(UUID.fromString(employeeId)), photoNumber, data, true);
        } catch (Exception e) {
            System.err.println("Ошибка установки фото: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }


    public static void addAccessLevelsToEmployee(String employeeID, String[] accessLevelIDs) { // Назначить уровни доступа сотруднику
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


    public static void removeAccessLevelFromEmployee(String employeeID, String[] accessLevelIDs) { // Удалить уровни доступа у сотрудника
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


    public static void setUseEmployeeParentAccessLevel(String employeeID, boolean isUseParentAccessLevel) { // Устанавливает флаг наследования доступов. Нужно снять (false) для ручного проставления доступа!!!
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

    public static void setEmployeeLocked(String id, boolean isLocked) {
        if (id == null) {
            throw new IllegalArgumentException("id is null");
        }
        lockAcsEmployee(new String[]{id}, isLocked);
    }

    public static void setEmployeesLocked(String[] ids, boolean isLocked) {
        lockAcsEmployee(ids, isLocked);
    }

    public static void lockAcsEmployee(String[] ids, boolean isLocked) { // Заблокировать или разблокировать сотрудников.
        try {
            if (networkCnfgService == null) {
                throw new IllegalStateException("networkCnfgService is not initialized. Call initServices() first.");
            }
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
    /* ВАЖНАЯ информация по работе с ключами
     * 1. У сотрудника может быть назначено только два ключа с порядковыми номерами 1 и 2
     *
     * 2. Если дата начала и окончания действия ключа не указана(StartDate и EndDate соответственно) то считается, что ключ выдается
     * на все время(действует бесконечно). Если указана только дата начала, то ключ действует с этой даты и до бесконечности.
     * Если указана только дата окончания действия, то ключ действует с текущего момента до момента наступления даты окончания действия ключа.
     *
     * 3. При попытке назначить ключ сотруднику может возникнуть ситтуация, когда ключ уже назначен другому сотруднику.
     * В этом случае допустимо воспользоваться методом ForceAssignAcsKeyForEmployee и переназначить ключ. Сценарий назначения ключа сотруднику в общем случает такой:
     * Попытка назначить ключ посредством метода AssignAcsKeyForEmployee, если возникает исключение AssignmentAcsKeyException с типом ошибки AssignmentAcsKeyErrorType.AcsKeyAlreadyAssignedToAnotherEmployee,
     * то принимается решение об продолжении операции назначения ключа посредством метода ForceAssignAcsKeyForEmployee, или отказе от операции
     */

    public static void removeKeyFromEmployee(String employeeId, int indexNumber) { // Забрать ключ у сотрудника
        try {
            networkCnfgService.assignAcsKeyForEmployee(employeeId, indexNumber, null, false);
        } catch (Exception e) {
            System.err.println("Ошибка снятия ключа: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static AcsKeyInfo assignAcsKeyForEmployee(String employeeId, int indexNumber, AcsKeySaveData keyData) { // Привязать ключ к сотруднику с трактовкой операции как недопустимой, если ключ уже присвоен другому сотруднику.
        try {
            return networkCnfgService.assignAcsKeyForEmployee(employeeId, indexNumber, keyData, false);
        } catch (Exception e) {
            System.err.println("Ошибка назначения ключа: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static AcsKeyInfo forceAssignAcsKeyForEmployee(String employeeId, int indexNumber, AcsKeySaveData keyData) { // Привязать ключ к сотруднику. Если ключ уже присвоен другому сотруднику, то он у него будет сброшен.
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
    /*  ВАЖНАЯ информация по работе с событиями
     *  1. Для постоянного мониторинга событий, происходящих на сервере, фильтр по дате/времени использовать нельзя (время сервера и клиента могут различаться)
     *  Каждое событие имеет номер, являющийся идентификатор записи(строки) в БД.
     *  Идентификаторы инкриментируются, поэтому у позднего события идентификатор всегда больше, чем у раннего. В связи с чем сценарий мониторинга событий
     *  сводится к цикличному вызову метода GetLastEvent, чтобы получить идентификатор последнего события, удовлетворяющего фильтру,
     *  принятие его в качестве максимального значения идентификатора и затем цикличный вызов GetEvents,
     *  поиск нового максимального идентификатора записи среди списка полученных событий, чтобы на последующей итерации вызвать метод,
     *  указав в качестве параметра "с какой записи следует вычитка события" это идентификатор.
     *  Следует устанавливать задержку между итерациями опроса. Величина задержки должна быть адекватна задаче, решаемой с помощью мониторинга событий.
     *  Безостановочно вызывать серверный метод не стоит.
     *
     *  2. Если же требуется просто снять данные за определенный период времени, то следует вызвать GetEvents, указав в параметрах нужные даты.
     *
     *  3. ВАЖНО. Очень нежелательно (особенно это касается постоянного мониторинга) получать события, используя в качестве одного из фильтров идентификаторы точек доступа,
     *  т.к. на реальном объекте их может быть не одна тысяча, что существенно замедляет выборку. Следует получить список точек доступа, после чего
     *  сопоставлять идентификаторы устройств в событиях с идентификаторами полученных точек доступа. Следует учитывать, что список точек доступа хоть и достаточно редко
     *  (часто на этапе пуско-наладки), но меняется, т.к. точки прохода периодически монтируются/демонтируются.
     */

    public static void trackEvents(String[] accessPointsIds) throws DatatypeConfigurationException { // Пример постоянного мониторинга событий для всех или определенных точек доступа по фильтру событий входа и выхода
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


    public static LogData getEvents(String[] accessPointsIds) throws DatatypeConfigurationException { // Пример получения событий для всех или определенных точек доступа по фильтру событий входа и выхода за январь
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
    public static List<LDriverFullInfo> getAllDrivers() { // Получить коллекцию всех драйверов устройств
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

    public static AcsAccessPointDriverInfo[] getAccessPointsDrivers2() { // Получение драйверов точек доступа, предварительно получив все дрйвера устройств. Лучше использовать GetAccessPointsDrivers2, т.к. набор типов точек доступа может расширяться.
        return getAccessPoints();
    }
   // отправляет команду (вызов метода) на устройство через SOAP-сервис networkService, используя операцию типа DeviceCallMethodOperation.
    public static void sendCommand(String connectionId, String commandName) { // Послать команду точке доступа
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

    private static boolean isEmployeeLocked(AcsEmployeeFull employee) {
        if (employee == null) {
            return false;
        }
        return Boolean.FALSE.equals(employee.isIsLocked());
    }

    private static String getEmployeeLastName(AcsEmployeeFull employee) {
        if (employee == null) {
            return "";
        }
        Object lastName = getValue(employee, "getLastName");
        return lastName != null ? lastName.toString() : "";
    }

    private static String getEmployeePositionName(AcsEmployeeFull employee) {
        if (employee == null || employee.getPosition() == null || employee.getPosition().getValue() == null) {
            return "";
        }
        if (employee.getPosition().getValue().getName() == null) {
            return "";
        }
        if (employee.getPosition().getValue().getName().getValue() == null) {
            return "";
        }
        return employee.getPosition().getValue().getName().getValue();
    }

    // ================================
// #region Пример использования
//    ID: 6d353b9b-352e-442f-ae24-70791992c1a3, LastName: Квочкин, FirstName: Алексей, SecondName: Юрьевич, Position:
//    ID: 55a16c7b-5b93-40f4-af8a-64dd9c5eeb79, LastName: Квочкин, FirstName: Алексей, SecondName: Юрьевич, Position:
//    ID: 8bcce3b1-2448-42f0-b61e-51bba707016f, GroupID: 901cb40e-fce2-47bb-9b0e-d3ca2087a22d, LastName: Квочкин, FirstName: Алексей, SecondName: Юрьевич
//    ID: eb1eb9e9-da50-412b-867b-9008bb3af985, GroupID: 901cb40e-fce2-47bb-9b0e-d3ca2087a22d, LastName: Мергазымова, FirstName: Ольга, SecondName: Владимировна
//    ID: c675452f-6881-426d-99a7-d7af2fc6b943, GroupID: 901cb40e-fce2-47bb-9b0e-d3ca2087a22d, LastName: Торопов, FirstName: Михаил, SecondName: Викторович
//    ID: e4f9bf7f-3bc0-4278-9e18-19693d1d92fb, GroupID: 901cb40e-fce2-47bb-9b0e-d3ca2087a22d, LastName: Жирнов, FirstName: Сергей, SecondName: Алексеевич
//    ID: cc4990aa-b309-479e-a484-65e4abe80dfe, GroupID: 901cb40e-fce2-47bb-9b0e-d3ca2087a22d, LastName: Кокурин, FirstName: Максим, SecondName: Романович
//    ID: 4bf9f60a-da45-4646-b6cd-f8b0bdbaad75, GroupID: 901cb40e-fce2-47bb-9b0e-d3ca2087a22d, LastName: Ермолаев, FirstName: Алексей, SecondName: Сергеевич
// ================================
    public static void printEmployeeGroups(List<AcsEmployeeGroup> groups, int depth) {
        if (groups == null || groups.isEmpty()) return;
        for (AcsEmployeeGroup group : groups) {
            // Выводим текущую группу с отступом
            String indent = "  ".repeat(depth); // 2 пробела на уровень
            String groupName = group.getName() != null ? group.getName().getValue() : "[No Name]";
            String groupId = group.getID() != null ? group.getID() : "[No ID]";
            System.out.println(indent + "└─ " + groupName + " (" + groupId + ")");

            // Получаем подгруппы как JAXBElement<ArrayOfAcsEmployeeGroup>
            JAXBElement<ArrayOfAcsEmployeeGroup> subGroupsElement = group.getEmployeeGroups();

            if (subGroupsElement != null) {
                ArrayOfAcsEmployeeGroup subGroups = subGroupsElement.getValue();
                if (subGroups != null && subGroups.getAcsEmployeeGroup() != null) {
                    // Передаём List<AcsEmployeeGroup> из ArrayOfAcsEmployeeGroup
                    printEmployeeGroups(subGroups.getAcsEmployeeGroup(), depth + 1);
                }
            }
        }
    }

    /**
     * Выводит дерево групп, начиная с одного корневого AcsEmployeeGroup
     */
    public static void printEmployeeGroup(AcsEmployeeGroup rootGroup, int depth) {
        if (rootGroup == null) return;

        // Выводим текущую группу
        String indent = "  ".repeat(depth);
        String groupName = rootGroup.getName() != null ? rootGroup.getName().getValue() : "[No Name]";
        String groupId = rootGroup.getID() != null ? rootGroup.getID() : "[No ID]";
        System.out.println(indent + "└─ " + groupName + " (" + groupId + ")");

        // Получаем подгруппы (JAXBElement<ArrayOfAcsEmployeeGroup>)
        JAXBElement<ArrayOfAcsEmployeeGroup> subGroupsElement = rootGroup.getEmployeeGroups();

        if (subGroupsElement != null) {
            ArrayOfAcsEmployeeGroup subGroups = subGroupsElement.getValue();

            if (subGroups != null && subGroups.getAcsEmployeeGroup() != null) {
                // Рекурсивно обрабатываем список подгрупп
                for (AcsEmployeeGroup childGroup : subGroups.getAcsEmployeeGroup()) {
                    printEmployeeGroup(childGroup, depth + 1);
                }
            }
        }
    }

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



            //Уровень доступа (вывод только PIONT ACCESS)
//TODO             getAccessLevelsSlim()
//            .forEach(ccessLevelsSlim -> {
//                System.out.print(ccessLevelsSlim.getId());
//                System.out.print(" " + ccessLevelsSlim.getName().getValue());
//                System.out.print(" " + ccessLevelsSlim.getDescription().getValue());
//                System.out.print(" " + ccessLevelsSlim.getEndDate().getValue());
//                System.out.println();
//            });

//TODO                    GetEmployeesByTabelNumber(766291);

            //            setEmployeeLocked("4dd89565-74f0-493f-9812-519242d8124d", false); //1. Блокировать / разблокировать пользователя - (4dd89565-74f0-493f-9812-519242d8124d - Карлышев А)

//            addEmailEmployee("77ec9c4f-3ee6-4ad3-a10d-527f8aff6359", "pchelintcevSV3@itsnn.ru", "рабочая почта"); //2. Добавить email
//TODO не работает            remoteEmailByID();
//TODO не работает            addEmployee();
//TODO         2.1.  Добавить нового пользователя
//            AcsEmployeeSlim acsEmployeeSlim = addEmployee(
//                    "Имя"
//                    , "Фамилия"
//                    , "Отчество"
//                    , 654321
//                    , "2129e300-520e-4ec3-a95a-8b5c7dfb34a7"
//                    , "901cb40e-fce2-47bb-9b0e-d3ca2087a22d"
//                    , "Комментарий тестового пользователя"
//                    , "Адрес регистрации пользователя"
//                    , "WWWW"
//                    , "ITSNN.RU");
//            System.out.println("Создан пользователь ID: "
//                    + acsEmployeeSlim.getID()
//                    + " Фамилия: " + acsEmployeeSlim.getFirstName().getValue()
//                    + " Имя: " + acsEmployeeSlim.getSecondName().getValue()
//                    + " Отчество: " + acsEmployeeSlim.getLastName().getValue()
//                    + " Табельный номер: " + acsEmployeeSlim.getNumber().getValue());
//            getEmployeesByGroupID("901cb40e-fce2-47bb-9b0e-d3ca2087a22d"); //2. Поиск сотрудников по ID Group

//TODO         2.2.            updateEmployeByID("8f3d00e6-a595-43fa-9d85-6252b426c8e1", testEmployee(), false); //изменение Пользователя (isLock = false - для изменения, isLock = true - без изменения(блокировка))
//            networkCnfgService.removeEmailAddress(arrayOfguid,false);
            //По IDGroup найти всех Employees
//            System.out.println("Поиск сотрудников по ID Group");
//TODO                      getEmployeesByGroupID("901cb40e-fce2-47bb-9b0e-d3ca2087a22d"); //3. Поиск сотрудников по ID Group
            //**************************
//TODO           getEmployee("Кокурин", "Максим", "Романович", true); //3.1. Поиск сотрудников по Фио
//            getEmployee("Ермолаев", "Алексей", "Сергеевич", true); // Поиск сотрудников по Фио
//TODO            getEmployeeById("cc4990aa-b309-479e-a484-65e4abe80dfe"); //3.2. Поиск сотрудников по ID сотрудника
//TODO            for (int i = 0; i < 31; i++) {
//TODO                getEmployeePassagesByDate("cc4990aa-b309-479e-a484-65e4abe80dfe", LocalDate.of(2026, 1, i+1)); //3.3. Поиск проходов по ID сотрудника
//TODO            }
            getEmployeePassagesByDate("4bf9f60a-da45-4646-b6cd-f8b0bdbaad75", LocalDate.of(2026, 1, 21)); // Поиск проходов по ID сотрудника

//TODO            getAllEmployees(); //3.4. Поиск всех сотрудников

            //TODO            String nameGroup = getGroupName("75c0f525-0851-4730-9edc-f16e955a32ca"); //4. Название Группы Пользователя
            //TODO            System.out.println(nameGroup);
            //TODO<начало>Вывод структуры группы из ID группы
//            AcsEmployeeGroup gp = networkService.getAcsEmployeeGroup("75c0f525-0851-4730-9edc-f16e955a32ca"); //4.1. Дерево групп (Вывод структуры группы из ID группы)
//            if (gp != null && gp.getEmployeeGroups() != null) {
//                if (!gp.isIsRemoved()) {
//                    printEmployeeGroup(gp, 0); // ✅ Теперь передаём один объект, а не список
//                }
//            }
            //TODO<конец>Вывод структуры группы из ID группы
            //TODO<начало>Вывод структуры группы из корневой группы
//            ArrayOfAcsEmployeeGroup gp = getEmployeeGroups();  // //4.2. Дерево групп -"75c0f525-0851-4730-9edc-f16e955a32ca"-ID Сотрудники новая
////             Выводим дерево с начальным отступом 0
//            if (gp != null && gp.getAcsEmployeeGroup() != null) {
//                printEmployeeGroups(gp.getAcsEmployeeGroup(), 0);
//            }
            //TODO<конец>Вывод структуры группы из корневой группы
//            ArrayOfguid arrayOfGuids = new ArrayOfguid(); //4.3.
//            arrayOfGuids.getGuid().add("75c0f525-0851-4730-9edc-f16e955a32ca");
//          ***
//            ArrayOfAcsEmployeeGroup temp_EmployeeGroups = networkService.getAcsEmployeeGroupsFull(false); //Аналог getEmployeeGroups
//            temp_EmployeeGroups.getAcsEmployeeGroup().forEach(acsEmployeeGroup -> System.out.println(acsEmployeeGroup.getID() + " - " + acsEmployeeGroup.getName().getValue()));
//          ***
//TODO ???       LUserGroupsData tt = networkService.getUserGroups(0,500,UserGroupSortedColumn.NAME, SortOrder.ASCENDING); //Показывает ЛЕВЫЕ группы!!!
//TODO ???       tt.getUserGroups().getValue().getLUserGroup().forEach(acsEmployeeGroup -> System.out.println(acsEmployeeGroup.getID() + " - " + acsEmployeeGroup.getName().getValue()));

//            ArrayOfClaimInfo tt = networkService.getClaimsForUserGroup("0fe4bb1a-7d11-457d-bda7-f6b3a0f315cc");
//        //tt.getUserGroups().getValue().getLUserGroup().forEach(acsEmployeeGroup -> System.out.println(acsEmployeeGroup.getID() + " - " + acsEmployeeGroup.getName().getValue()));

        } catch (Exception e) {
            System.err.println("Ошибка при выполнении поиска: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static boolean updateEmployeByID(String ID, AcsEmployeeSaveData employeeData, boolean isLock) {
        boolean changeLock;
        if (isLock) {
            changeLock = true;
        } else changeLock = isLock;
        employeeData.setIsChangeLocked(changeLock);
        // ✅ Вызываем сервис
//        AcsEmployeeSlim result = saveAcsEmployee(ID, employeeData); //"8f3d00e6-a595-43fa-9d85-6252b426c8e1"
        try {
            saveAcsEmployee(ID, employeeData); //"8f3d00e6-a595-43fa-9d85-6252b426c8e1"
//            result = networkCnfgService.addAcsEmployee(positionGroup, employeeData);
//        } catch (ILNetworkConfigurationServiceAddAcsEmployeeArgumentNullExceptionFaultFaultMessage e) {
//            System.err.println("Ошибка: обязательное поле не передано — " + e.getFaultInfo().toString());
//        } catch (ILNetworkConfigurationServiceAddAcsEmployeeDataAlreadyExistsExceptionFaultFaultMessage e) {
//            System.err.println("Ошибка: сотрудник с такими данными уже существует — " + e.getFaultInfo().toString());
//        } catch (ILNetworkConfigurationServiceAddAcsEmployeeDataNotFoundExceptionFaultFaultMessage e) {
//            System.err.println("Ошибка: группа или должность не найдены — " + e.getFaultInfo().toString());
        } catch (Exception e) {
            System.err.println("Неожиданная ошибка: " + e.getMessage());
            return false;
        }
        return true;

    }

    private static AcsEmployeeSaveData testEmployee() {
        QName EMPLOYEE_POSITION_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "EmployeePositionID"
        );
        QName EMPLOYEE_FIRSTNAME_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "FirstName"
        );
        QName EMPLOYEE_LASTNAME_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "LastName"
        );
        QName EMPLOYEE_SECONDNAME_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "SecondName"
        );
        QName EMPLOYEE_COMMENT_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "Comment"
        );
        QName EMPLOYEE_ADRESSREG_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "RegistrationAddress"
        );
        QName EMPLOYEE_NUMBER_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "Number"
        );
        QName EMPLOYEE_PASPORTIISUE_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "PassportIssue"
        );
        QName EMPLOYEE_PASPORTNOMBER_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "PassportNumber"
        );

        AcsEmployeeSaveData employeeData = new AcsEmployeeSaveData(); // Создаём объект данных сотрудника

        // ✅ Оборачиваем в JAXBElement
//        JAXBElement<String> employeePositionID = new JAXBElement<>(
//                EMPLOYEE_POSITION_ID_QNAME,   // Имя и пространство имён элемента
//                String.class,                 // Тип значения
//                position                       // Значение — ID должности из вашей системы
//        );
        JAXBElement<String> employeeFirstName = new JAXBElement<>(
                EMPLOYEE_FIRSTNAME_ID_QNAME,
                String.class,
                "Тест Имя"
        );
        JAXBElement<String> employeeLastName = new JAXBElement<>(
                EMPLOYEE_LASTNAME_ID_QNAME,
                String.class,
                "Тест Фамилия"
        );
        JAXBElement<String> employeeSecondName = new JAXBElement<>(
                EMPLOYEE_SECONDNAME_ID_QNAME,
                String.class,
                "Тест Отчество"
        );
        JAXBElement<String> employeeComment = new JAXBElement<>(
                EMPLOYEE_COMMENT_ID_QNAME,
                String.class,
                "Тест комментарий"
        );
        JAXBElement<String> employeeAdressReg = new JAXBElement<>(
                EMPLOYEE_ADRESSREG_ID_QNAME,
                String.class,
                "Тест Адрес регистрации"
        );
        JAXBElement<String> employeePassportIISUE = new JAXBElement<>(
                EMPLOYEE_PASPORTIISUE_ID_QNAME,
                String.class,
                "TEST"
        );
        JAXBElement<String> employeePassportNumber = new JAXBElement<>(
                EMPLOYEE_PASPORTNOMBER_ID_QNAME,
                String.class,
                "333000"
        );
        JAXBElement<Integer> employeeNumber = new JAXBElement<>(
                EMPLOYEE_NUMBER_ID_QNAME,
                Integer.class,
                121212
        );
        // ✅ Устанавливаем другие поля (опционально)
//        employeeData.setEmployeePositionID(employeePositionID);
//        employeeData.setIsChangeLocked(changeLock);   // true — запретить изменение /false-разрешить
        employeeData.setIsChangePin(false);     // false — не требовать смены PIN
        employeeData.setFirstName(employeeFirstName);
        employeeData.setLastName(employeeLastName);
        employeeData.setSecondName(employeeSecondName);
        employeeData.setNumber(employeeNumber);
//        employeeData.setEmployeePositionID(employeePositionID);
        employeeData.setComment(employeeComment);
        employeeData.setRegistrationAddress(employeeAdressReg);
        employeeData.setPassportIssue(employeePassportIISUE);
        employeeData.setPassportNumber(employeePassportNumber);
        return employeeData;
    }

    private static List<AcsAccessLevelSlimInfo> getAccessLevelsSlim() { //Получение всех уровней доступа
        List<AcsAccessLevelSlimInfo> accessLevels = networkService.getAcsAccessLevelsSlimInfo().getAcsAccessLevelSlimInfo();

        return accessLevels.stream()
                .filter(tt -> !tt.isIsRemoved()) // фильтруем удалённые
                .sorted(Comparator.comparing(
                        tt -> {
                            String name = tt.getName() != null ? tt.getName().getValue() : "";
                            return name.length() >= 4 ? name.substring(0, 4) : name; // первые 4 или всё, если меньше
                        }
                        ))
                .collect(Collectors.toList());
    }

    private static ArrayOfAcsEmployeeFull GetEmployeesByTabelNumber(Integer tabelNumber) {
        ArrayOfint arrayTabelNumber=new ArrayOfint();
        arrayTabelNumber.getInt().add(tabelNumber);
        ArrayOfAcsEmployeeFull arrayOfAcsEmployeeFull = networkService.getAcsEmployeesByTableNumbers(arrayTabelNumber);
        if (arrayOfAcsEmployeeFull.getAcsEmployeeFull().size()==0) {
            return arrayOfAcsEmployeeFull;
        }
        for (  AcsEmployeeFull AcsEmployee:  arrayOfAcsEmployeeFull.getAcsEmployeeFull()) {
            System.out.println(AcsEmployee.getID()
                    + " "  + AcsEmployee.getLastName().getValue()
                    + " " + AcsEmployee.getFirstName().getValue()
                    + " "  + AcsEmployee.getSecondName().getValue()
                    + " "  + AcsEmployee.getEmployeeGroupID()
                    + " "  + AcsEmployee.getNumber().getValue()
                    + " isIsRemoved: " + AcsEmployee.isIsRemoved().booleanValue());
        }
        return arrayOfAcsEmployeeFull;
    }

    private static AcsEmployeeSlim addEmployee(String firstname, String lastname, String secondname, Integer tabelNumber, String position, String positionGroup, String Comment, String AdressReg, String PassportIISUE, String PassportNumber) {

        QName EMPLOYEE_POSITION_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "EmployeePositionID"
        );
        QName EMPLOYEE_FIRSTNAME_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "FirstName"
        );
        QName EMPLOYEE_LASTNAME_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "LastName"
        );
        QName EMPLOYEE_SECONDNAME_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "SecondName"
        );
        QName EMPLOYEE_COMMENT_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "Comment"
        );
        QName EMPLOYEE_ADRESSREG_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "RegistrationAddress"
        );
        QName EMPLOYEE_NUMBER_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "Number"
        );
        QName EMPLOYEE_PASPORTIISUE_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "PassportIssue"
        );
        QName EMPLOYEE_PASPORTNOMBER_ID_QNAME = new QName(
                "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ACS.Employees",
                "PassportNumber"
        );

        AcsEmployeeSaveData employeeData = new AcsEmployeeSaveData(); // Создаём объект данных сотрудника
        // ✅ Оборачиваем в JAXBElement
        JAXBElement<String> employeePositionID = new JAXBElement<>(
                EMPLOYEE_POSITION_ID_QNAME,   // Имя и пространство имён элемента
                String.class,                 // Тип значения
                position                       // Значение — ID должности из вашей системы
        );
        JAXBElement<String> employeeFirstName = new JAXBElement<>(
                EMPLOYEE_FIRSTNAME_ID_QNAME,
                String.class,
                firstname
        );
        JAXBElement<String> employeeLastName = new JAXBElement<>(
                EMPLOYEE_LASTNAME_ID_QNAME,
                String.class,
                lastname
        );
        JAXBElement<String> employeeSecondName = new JAXBElement<>(
                EMPLOYEE_SECONDNAME_ID_QNAME,
                String.class,
                secondname
        );
        JAXBElement<String> employeeComment = new JAXBElement<>(
                EMPLOYEE_COMMENT_ID_QNAME,
                String.class,
                Comment
        );
        JAXBElement<String> employeeAdressReg = new JAXBElement<>(
                EMPLOYEE_ADRESSREG_ID_QNAME,
                String.class,
                AdressReg
        );
        JAXBElement<String> employeePassportIISUE = new JAXBElement<>(
                EMPLOYEE_PASPORTIISUE_ID_QNAME,
                String.class,
                PassportIISUE
        );
        JAXBElement<String> employeePassportNumber = new JAXBElement<>(
                EMPLOYEE_PASPORTNOMBER_ID_QNAME,
                String.class,
                PassportNumber
        );
        JAXBElement<Integer> employeeNumber = new JAXBElement<>(
                EMPLOYEE_NUMBER_ID_QNAME,
                Integer.class,
                tabelNumber
        );
        // ✅ Устанавливаем другие поля (опционально)
        employeeData.setEmployeePositionID(employeePositionID);
        employeeData.setIsChangeLocked(true);   // true — запретить изменение
        employeeData.setIsChangePin(false);     // false — не требовать смены PIN
        employeeData.setFirstName(employeeFirstName);
        employeeData.setLastName(employeeLastName);
        employeeData.setSecondName(employeeSecondName);
        employeeData.setNumber(employeeNumber);
        employeeData.setEmployeePositionID(employeePositionID);
        employeeData.setComment(employeeComment);
        employeeData.setRegistrationAddress(employeeAdressReg);
        employeeData.setPassportIssue(employeePassportIISUE);
        employeeData.setPassportNumber(employeePassportNumber);
        // ✅ Вызываем сервис
        AcsEmployeeSlim result = new AcsEmployeeSlim();

        try {
            result = networkCnfgService.addAcsEmployee(positionGroup, employeeData);
        } catch (ILNetworkConfigurationServiceAddAcsEmployeeArgumentNullExceptionFaultFaultMessage e) {
            System.err.println("Ошибка: обязательное поле не передано — " + e.getFaultInfo().toString());
        } catch (ILNetworkConfigurationServiceAddAcsEmployeeDataAlreadyExistsExceptionFaultFaultMessage e) {
            System.err.println("Ошибка: сотрудник с такими данными уже существует — " + e.getFaultInfo().toString());
        } catch (ILNetworkConfigurationServiceAddAcsEmployeeDataNotFoundExceptionFaultFaultMessage e) {
            System.err.println("Ошибка: группа или должность не найдены — " + e.getFaultInfo().toString());
        } catch (Exception e) {
            System.err.println("Неожиданная ошибка: " + e.getMessage());
        }
        return result;
    }

    private static void remoteEmailByID() {
        try {
            ArrayOfguid subjectIDs = new ArrayOfguid();
            subjectIDs.getGuid().add("77ec9c4f-3ee6-4ad3-a10d-527f8aff6359");

            // ✅ Передаём строку, а не UUID — потому что JAXB генерирует List<String>
            //                ArrayOfguidWrapper wrapper = new ArrayOfguidWrapper();
//                wrapper.getIds().add("77ec9c4f-3ee6-4ad3-a10d-527f8aff6359");
//                networkCnfgService.removeEmailAddress(wrapper.toOriginal(), false);
            networkCnfgService.removeEmailAddress(subjectIDs, false);
            System.out.println("Email address successfully removed.");

        } catch (SOAPFaultException e) {
            System.err.println("SOAP Fault: " + e.getFault().getFaultString());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void addEmailEmployee(String IDEmployee, String email, String description) throws ILNetworkConfigurationServiceAddEmailAddressDataAlreadyExistsExceptionFaultFaultMessage,
            ILNetworkConfigurationServiceAddEmailAddressArgumentExceptionFaultFaultMessage,
            ILNetworkConfigurationServiceAddEmailAddressDataNotFoundExceptionFaultFaultMessage,
            ILNetworkConfigurationServiceAddEmailAddressArgumentNullExceptionFaultFaultMessage,
            ILNetworkConfigurationServiceAddEmailAddressArgumentOutOfRangeExceptionFaultFaultMessage {

        // 🔒 Валидация входных данных
        if (IDEmployee == null || IDEmployee.trim().isEmpty()) {
            throw new IllegalArgumentException("IDEmployee cannot be null or empty");
        }
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
        if (description == null) {
            description = "";
        }

        // 🔍 Получаем namespace динамически (без жёсткого кодирования)
//        try {
        //TODO выяснить где взять динамически namespace
//            Field emailField = EmailAddressSaveData.class.getDeclaredField("email");
//            String namespace = emailField.getAnnotation(XmlElement.class).namespace();
        String namespace = "http://schemas.datacontract.org/2004/07/VVIInvestment.RusGuard.DAL.Entities.Entity.ContactInformation";
        // ✅ Создаём все элементы через JAXBElement с правильным namespace
        JAXBElement<String> emailElement = new JAXBElement<>(
                new QName(namespace, "Email"),
                String.class,
                email
        );
        JAXBElement<String> descriptionElement = new JAXBElement<>(
                new QName(namespace, "Description"),
                String.class,
                description
        );
        Integer emailOrderElement = 1;

        // ✅ Собираем объект
        EmailAddressSaveData data = new EmailAddressSaveData();
        data.setEmail(emailElement);
        data.setDescription(descriptionElement);
        data.setEmailOrder(emailOrderElement); // ✅ Важно: не setEmailOrder(1)!

        // 🔍 Проверка сервиса
        if (networkCnfgService == null) {
            throw new IllegalStateException("Network configuration service is not initialized");
        }

        // ✅ Вызов сервиса с обработкой исключений
        try {
            networkCnfgService.addEmailAddress(
                    EmailAddressOwner.EMPLOYEE,
                    IDEmployee,
                    data,
                    true
            );
            System.out.printf("Email %s successfully added for employee %s", email, IDEmployee);
        } catch (ILNetworkConfigurationServiceAddEmailAddressDataAlreadyExistsExceptionFaultFaultMessage e) {
            System.out.printf("Email %s already exists for employee %s", email, IDEmployee);
            throw e;
        } catch (Exception e) {
            System.out.printf("Failed to add email %s for employee %s: %s, %s", email, IDEmployee, e.getMessage(), e);
            throw new RuntimeException("Failed to add email: " + e.getMessage(), e);
        }

//        } catch (NoSuchFieldException e) {
//            throw new IllegalStateException("Cannot find 'email' field in EmailAddressSaveData class: ", e);
//        }
    }

    private static ArrayOfAcsEmployeeGroup getEmployeeGroups() {
        ArrayOfAcsEmployeeGroup temp_EmployeeGroups = networkService.getAcsEmployeeGroups();
//        temp_EmployeeGroups.getAcsEmployeeGroup().forEach(acsEmployeeGroup -> System.out.println(acsEmployeeGroup.getID() + " - " + acsEmployeeGroup.getName().getValue()));
        return temp_EmployeeGroups;
    }

    private static String getGroupName(String IDGroup) {
        AcsEmployeeGroup temp_EmployeeGroup = networkService.getAcsEmployeeGroup(IDGroup);

        String nameOrEmpty = temp_EmployeeGroup != null && !temp_EmployeeGroup.isIsRemoved() && temp_EmployeeGroup.getName() != null ? temp_EmployeeGroup.getName().getValue() : "Удалена: ";
        return nameOrEmpty;
    }

    private static void getEmployeesByGroupID(String idGroup) throws ILNetworkServiceGetAcsEmployeesGuidsByGroupsDataNotFoundExceptionFaultFaultMessage {
        ArrayOfguid employeesGuids = networkService.getAcsEmployeesGuidsByGroups(
                toUuidArray(new String[]{idGroup}),
                false
        );
        if (employeesGuids != null && employeesGuids.getGuid() != null) {
            List<AcsEmployeeFull> employees = new ArrayList<>();
            for (String employeeId : employeesGuids.getGuid()) {
                AcsEmployeeFull employee = getAcsEmployee(employeeId);
                if (employee != null) {
                    employees.add(employee);
                }
            }
            employees.sort(
                    Comparator
                            .comparing((AcsEmployeeFull e) -> !isEmployeeLocked(e))
                            .thenComparing(RusGuardAcsIntegrationSample::getEmployeeLastName, String.CASE_INSENSITIVE_ORDER)
            );

            for (AcsEmployeeFull employee : employees) {
                getEmployeeById(employee.getID());
            }
        }
    }

    private static void getEmployee(String lastName, String firstName, String secondName, boolean isLock) {
        // Создаем условие поиска
        SearchCondition searchCondition = new SearchCondition();

        searchCondition.setIsGlobalSearch(true);
        searchCondition.setIncludeRemoved(true);

        // Устанавливаем фамилию для поиска
        JAXBElement<String> lastNameElement = new JAXBElement<>(
                new QName(NS_EMPLOYEES, "LastName"),
                String.class,
                lastName
        );
        searchCondition.setLastName(lastNameElement);

        // Устанавливаем имя для поиска
        JAXBElement<String> firstNameElement = new JAXBElement<>(
                new QName(NS_EMPLOYEES, "FirstName"),
                String.class,
                firstName
        );
        searchCondition.setFirstName(firstNameElement);

        // Устанавливаем отчество для поиска
        JAXBElement<String> secondNameElement = new JAXBElement<>(
                new QName(NS_EMPLOYEES, "SecondName"),
                String.class,
                secondName
        );
        searchCondition.setSecondName(secondNameElement);

        // Выполняем поиск
        System.out.println("Выполнение поиска сотрудников...");
        ArrayOfAcsEmployee result = networkService.findEmployees(searchCondition);

        String empLastName = "";
        String empFirstName = "";
        String empSecondName = "";
        String positionName = "";
        // Обрабатываем результаты
        if (result != null && result.getAcsEmployee() != null && !result.getAcsEmployee().isEmpty()) {
            System.out.println("Найдено сотрудников: " + result.getAcsEmployee().size());
            java.util.List<AcsEmployeeFull> employees = new java.util.ArrayList<>();
            for (AcsEmployee employee : result.getAcsEmployee()) {
                AcsEmployeeFull fullEmployee = getAcsEmployee(employee.getEmployeeID());
                if (fullEmployee != null && (!isLock || !fullEmployee.isIsLocked())) {
                    employees.add(fullEmployee);
                }
            }

            employees.sort(
                    java.util.Comparator
                            .comparing((AcsEmployeeFull e) -> !isEmployeeLocked(e))
                            .thenComparing(RusGuardAcsIntegrationSample::getEmployeeLastName, String.CASE_INSENSITIVE_ORDER)
            );

            for (AcsEmployeeFull fullEmployee : employees) {
                empLastName = getValue(fullEmployee, "getLastName") != null ? getValue(fullEmployee, "getLastName").toString() : "";
                empFirstName = getValue(fullEmployee, "getFirstName") != null ? getValue(fullEmployee, "getFirstName").toString() : "";
                empSecondName = getValue(fullEmployee, "getSecondName") != null ? getValue(fullEmployee, "getSecondName").toString() : "";
                positionName = getEmployeePositionName(fullEmployee);

                System.out.println("ID: " + Objects.requireNonNull(fullEmployee).getID() +
                        ", LastName: " + empLastName +
                        ", FirstName: " + empFirstName +
                        ", SecondName: " + empSecondName +
                        ", Position: " + positionName);
            }
        } else {
            System.out.println("Сотрудники не найдены по заданным критериям");

            // Попробуем найти хотя бы по фамилии
            searchCondition = new SearchCondition();
            searchCondition.setIsGlobalSearch(true);
            searchCondition.setIncludeRemoved(true);

            searchCondition.setLastName(lastNameElement);

            result = networkService.findEmployees(searchCondition);

            if (result != null && result.getAcsEmployee() != null && !result.getAcsEmployee().isEmpty()) {
                System.out.println("Найдено сотрудников по фамилии: " + result.getAcsEmployee().size());
                for (AcsEmployee employee : result.getAcsEmployee()) {
                    // Загружаем полную информацию о сотруднике по ID
                    AcsEmployeeFull fullEmployee = getAcsEmployee(employee.getEmployeeID());
                    if (fullEmployee != null) {
                        empLastName = getValue(fullEmployee, "getLastName") != null ? getValue(fullEmployee, "getLastName").toString() : "";
                        empFirstName = getValue(fullEmployee, "getFirstName") != null ? getValue(fullEmployee, "getFirstName").toString() : "";
                        empSecondName = getValue(fullEmployee, "getSecondName") != null ? getValue(fullEmployee, "getSecondName").toString() : "";

                        positionName = getPositionName(fullEmployee);
                        System.out.println("ID: " + fullEmployee.getID() +
                                ", LastName: " + empLastName +
                                ", FirstName: " + empFirstName +
                                ", SecondName: " + empSecondName +
                                ", Position: " + positionName);
                    } else {
                        // Если не удалось загрузить полную информацию, используем данные из результата поиска
                        empLastName = getValue(employee, "getLastName") != null ? getValue(employee, "getLastName").toString() : "";
                        empFirstName = getValue(employee, "getFirstName") != null ? getValue(employee, "getFirstName").toString() : "";
                        empSecondName = getValue(employee, "getSecondName") != null ? getValue(employee, "getSecondName").toString() : "";

                        positionName = getPositionName(employee);
                        System.out.println("ID: " + employee.getEmployeeID() +
                                ", LastName: " + empLastName +
                                ", FirstName: " + empFirstName +
                                ", SecondName: " + empSecondName +
                                ", Position: " + positionName);
                    }
                }
            } else {
                System.out.println("Сотрудники не найдены даже по фамилии");
            }
        }
    }

    private static void getEmployeeById(String id) {
//        System.out.println("Поиск сотрудника по ID: " + id);
        try {
            AcsEmployeeFull employee = getAcsEmployee(id);
            if (employee == null) {
                System.out.println("Сотрудник не найден");
                return;
            }
            String positionName = employee.getPosition().getValue().getName().getValue(); //Должность
            System.out.println(
                    "ID: " + getValue(employee, "getID") +
                            ", GroupID: " + getValue(employee, "getEmployeeGroupID") +
                            ", isLocked " + employee.isIsLocked().toString() +
                            ", LastName: " + getValue(employee, "getLastName") +
                            ", FirstName: " + getValue(employee, "getFirstName") +
                            ", SecondName: " + getValue(employee, "getSecondName") +
                            ", Position: " + positionName
            );

        } catch (Exception e) {
            System.err.println("Ошибка поиска по ID: " + e.getMessage());
            e.printStackTrace();
        }
    }


    private static void getEmployeePassagesByDate(String employeeId, LocalDate date) {
        if (employeeId == null || employeeId.isBlank()) {
            throw new IllegalArgumentException("employeeId is blank");
        }
        if (date == null) {
            throw new IllegalArgumentException("date is null");
        }

        System.out.println("Поиск проходов/событий сотрудника за дату: " + date + ", employeeId=" + employeeId);

        try {
            com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid subjectIDs = new com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid();
            subjectIDs.getGuid().add(String.valueOf(UUID.fromString(employeeId)));

            ZoneId zoneId = ZoneId.systemDefault();
            LocalDateTime startLdt = date.atStartOfDay();
            LocalDateTime endExclusiveLdt = date.plusDays(1).atStartOfDay();

            XMLGregorianCalendar fromDateTime = toXmlGregorianCalendar(ZonedDateTime.of(startLdt, zoneId));
            XMLGregorianCalendar toDateTime = toXmlGregorianCalendar(ZonedDateTime.of(endExclusiveLdt, zoneId));

            org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity.LogData logData = networkService.getEvents(
                    0L,
                    fromDateTime,
                    toDateTime,
                    null,
                    null,
                    subjectIDs,
                    LogSubjectType.EMPLOYEE,
                    0,
                    1000,
                    LogMessageSortedColumn.DATE_TIME,
                    SortOrder.ASCENDING
            );

            if (logData == null || logData.getMessages() == null || logData.getMessages().getValue() == null
                    || logData.getMessages().getValue().getLogMessage() == null
                    || logData.getMessages().getValue().getLogMessage().isEmpty()) {
                System.out.println("Проходы/события не найдены");
                return;
            }

            java.util.List<LogMessage> messages = logData.getMessages().getValue().getLogMessage();
            System.out.println("Найдено событий: " + messages.size());

            for (LogMessage msg : messages) {
                if (msg == null) {
                    continue;
                }

                System.out.println(
                        "DateTime: " + msg.getDateTime() +
                                ", Type: " + msg.getLogMessageType() +
                                ", SubType: " + msg.getLogMessageSubType() +
                                ", Message: " + (msg.getMessage() != null ? msg.getMessage().getValue() : "")
                );
            }

        } catch (Exception e) {
            System.err.println("Ошибка получения проходов/событий: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static XMLGregorianCalendar toXmlGregorianCalendar(ZonedDateTime zdt) {
        try {
            GregorianCalendar gc = GregorianCalendar.from(zdt);
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
        } catch (Exception e) {
            throw new RuntimeException(e);
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

    private static String getPositionName(Object fullEmployee) {
        String positionName = "";
        Object positionObj = getValue(fullEmployee, "getPosition");
        if (positionObj != null && !(positionObj instanceof String && positionObj.equals(""))) {
            if (positionObj instanceof JAXBElement) {
                Object positionValue = ((JAXBElement<?>) positionObj).getValue();
                if (positionValue != null) {
                    // Попробуем получить имя должности через getValue метод
                    Object nameValue = getValue(positionValue, "getName");
                    if (nameValue != null && !nameValue.toString().isEmpty() && !(nameValue instanceof String && nameValue.equals(""))) {
                        positionName = nameValue.toString();
                    } else {
                        // Если getName не сработал, пробуем другие возможные методы
                        try {
                            java.lang.reflect.Method[] methods = positionValue.getClass().getMethods();
                            for (java.lang.reflect.Method method : methods) {
                                if (method.getName().toLowerCase().contains("name") && method.getParameterCount() == 0) {
                                    Object result = method.invoke(positionValue);
                                    if (result != null) {
                                        positionName = result.toString();
                                        break;
                                    }
                                }
                            }
                        } catch (Exception e) {
                            // Если не удалось получить название, возвращаем toString() объекта
                            positionName = positionValue.toString();
                        }
                    }
                }
            } else {
                positionName = positionObj != null ? positionObj.toString() : "";
            }
        }
        return positionName;
    }
}
