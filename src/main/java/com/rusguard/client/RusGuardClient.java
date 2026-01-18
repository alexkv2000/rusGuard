package com.rusguard.client;

import com.rusguard.client.*;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.ws.BindingProvider;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.AcsEmployee;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.ArrayOfAcsEmployee;
import org.datacontract.schemas._2004._07.vviinvestment_rusguard_dal_entities_entity_acs.SearchCondition;
import org.tempuri.LNetworkService;

import javax.xml.namespace.QName;
import java.net.URL;
import java.util.List;

public class RusGuardClient {
    public static void main(String[] args) {
        try {
            // 1. Загружаем WSDL
            URL wsdlUrl = RusGuardClient.class.getClassLoader()
                    .getResource("wsdl/LNetworkServer/LNetworkService.wsdl");
            if (wsdlUrl == null) {
                System.out.println("ОШИБКА: Не найден WSDL файл!");
                return;
            }
            LNetworkService service = new LNetworkService(wsdlUrl);

            // 2. Получаем порт
            ILNetworkService port = service.getBasicHttpBindingILNetworkService();

            // 3. Устанавливаем адрес сервиса и аутентификацию
            BindingProvider bp = (BindingProvider) port;
            String serverAddress = "http://scud-1.gaz.ru/LNetworkServer/LNetworkService.svc";
            bp.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, serverAddress);
            bp.getRequestContext().put(BindingProvider.USERNAME_PROPERTY, "KvochkinAY");
            bp.getRequestContext().put(BindingProvider.PASSWORD_PROPERTY, "ваш_пароль");

            System.out.println("=== Подключение установлено ===");

            // 4. Готовим параметры поиска С JAXBElement
            SearchCondition searchParams = new SearchCondition();

            // Правильное создание JAXBElement для имени
            // Namespace обычно берется из targetNamespace WSDL
            String namespace = "http://www.rusguardsecurity.ru";

            // Вариант поиска по имени
            JAXBElement<String> firstNameElem = new JAXBElement<>(
                    new QName(namespace, "FirstName"),
                    String.class,
                    "Квочкин"
            );
            searchParams.setFirstName(firstNameElem);

            // Можно также добавить поиск по фамилии
            JAXBElement<String> lastNameElem = new JAXBElement<>(
                    new QName(namespace, "LastName"),
                    String.class,
                    "Алексей" // или другая фамилия
            );
            searchParams.setLastName(lastNameElem);

            System.out.println("Параметры поиска установлены");
            System.out.println("Имя: Квочкин");

            // 5. Вызываем метод
            System.out.println("Выполняем поиск сотрудников...");
            ArrayOfAcsEmployee result = port.findEmployees(searchParams);

            if (result == null) {
                System.out.println("Сервис вернул null.");
                return;
            }

            // 6. Получаем список сотрудников
            // Попробуем разные варианты получения списка
            List<AcsEmployee> employeeList = null;

            try {
                employeeList = result.getAcsEmployee();
                System.out.println("Используется метод: getAcsEmployee()");
            } catch (Exception e1) {
                try {
                    employeeList = result.getAcsEmployee();
                    System.out.println("Используется метод: getValue()");
                } catch (Exception e2) {
                    System.out.println("Ищу метод через рефлексию...");
                    // Поиск через рефлексию
                    for (java.lang.reflect.Method method : result.getClass().getDeclaredMethods()) {
                        if (method.getName().startsWith("get") &&
                                List.class.isAssignableFrom(method.getReturnType())) {
                            try {
                                employeeList = (List<AcsEmployee>) method.invoke(result);
                                System.out.println("Найден метод: " + method.getName());
                                break;
                            } catch (Exception ignored) {}
                        }
                    }
                }
            }

            // 7. Обрабатываем результат
            System.out.println("\n=== РЕЗУЛЬТАТ ===");

            if (employeeList != null && !employeeList.isEmpty()) {
                System.out.println("Найдено сотрудников: " + employeeList.size());
                System.out.println("\nСписок сотрудников:");

                for (int i = 0; i < employeeList.size(); i++) {
                    AcsEmployee emp = employeeList.get(i);

                    System.out.printf("%3d. ID: %d, ГруппаID: %d%n",
                            i + 1,
                            emp.getEmployeeID() != null ? emp.getEmployeeID() : 0,
                            emp.getGroupID() != null ? emp.getGroupID() : 0);

                    // Дополнительно: вывод всех доступных полей первого сотрудника
                    if (i == 0) {
                        System.out.println("    Дополнительная информация (все геттеры):");
                        for (java.lang.reflect.Method m : emp.getClass().getDeclaredMethods()) {
                            if (m.getName().startsWith("get") && m.getParameterCount() == 0) {
                                try {
                                    Object value = m.invoke(emp);
                                    if (value != null && !value.toString().isEmpty()) {
                                        System.out.println("      " + m.getName() + " = " + value);
                                    }
                                } catch (Exception e) {
                                    // игнорируем
                                }
                            }
                        }
                    }
                }
            } else {
                System.out.println("Сотрудники не найдены.");
                System.out.println("Попробуйте другие параметры поиска:");
                System.out.println("- Не указывать имя (получить всех)");
                System.out.println("- Использовать setTableNumber для поиска по табельному номеру");
                System.out.println("- Использовать setLastName для поиска по фамилии");
            }

        } catch (Exception e) {
            System.err.println("\n=== ОШИБКА ===");
            e.printStackTrace();

            // Полезная информация для отладки
            System.err.println("\nДля отладки JAXBElement:");
            System.err.println("1. Посмотрите сгенерированный SearchCondition.java");
            System.err.println("2. Найдите метод setFirstName и посмотрите его параметр");
            System.err.println("3. Обычно это: setFirstName(JAXBElement<String> value)");
        }
    }
}