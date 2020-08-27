# Saml configuration
This fork of Rundeck supports SAML authentication as well as login with Accenture SSO. 

## LOGIN/PWD AUTHENTICATION
Login/pwd authentication is the default mode in Rundeck, we did not change anything related to that.

## SAML AUTHENTICATION
To enable SAML authentication, you need to start Rundeck with additional properties, e.g.: 

-Drundeck.samlidp='https://keycloak.fr/auth/realms/my_realm/protocol/saml/descriptor' -Drundeck.samlclient='saml-test'

Here are the additional parameters that need to be configured:

| Parameter        | Description           | Mandatory | Default  |
| :----------------: |:---------------------:| :------: | :-----------: | 
| rundeck.samlidp      | URL of the SAML metadata endpoint of the IdP | Y | n/a |
| rundeck.samlclient   | client identifier used by Rundeck when contacting the IdP | Y | n/a |


## ACCENTURE SSO
In the same way, additionnal parameters need to be configured to enable Accenture SSO Login

| Parameter        | Description           | Mandatory | Default  |
| :---------------- |:---------------------:| :------: | :-----------: | 
| rundeck.accenturesso      | Flag indicating that Accenture SSO must be used (put a non null value) | Y | n/a |
| rundeck.security.authorization.accenturesso.idpUrl   | Accenture SSO endpoint | N | https://aiam.accenture.com/openam/saml2/jsp/applogin.jsp |
| rundeck.security.authorization.accenturesso.rundeckUrl   | Rundeck external URL | N | retrieved from login HTTP request |
| rundeck.security.authorization.accenturesso.pemFile   | Certificate used to validate SAML signature (should be a valid resource url) | N | classpath:/tokensigning.accenture.com.pem |
| rundeck.security.authorization.accenturesso.defaultRoles   | Roles assigned to Accenture users by default | N | empty |

Here is an example command line:

java -jar -Drundeck.accenturesso='enabled' -Drundeck.security.authorization.accenturesso.defaultRoles=admin,user -Drundeck.security.authorization.accenturesso.pemFile=file:/opt/rundeck/cert.pem  rundeck-3.3.1-SNAPSHOT.war
