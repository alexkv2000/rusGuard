//собрать сертификат по ссылке
keytool -printcert -rfc -sslserver scud-1.gaz.ru:443 > scud1.crt
//импортировать в $JAVA_HOME/lib/security/cacerts
keytool -importcert -file scud1.crt -keystore $JAVA_HOME/lib/security/cacerts -alias scud1 -storepass changeit