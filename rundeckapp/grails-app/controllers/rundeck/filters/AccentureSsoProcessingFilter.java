/* Copyright 2009 Vladimir Schäfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package rundeck.filters;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class AccentureSsoProcessingFilter extends AbstractAuthenticationProcessingFilter {

    protected final static Logger logger = LoggerFactory.getLogger(AccentureSsoProcessingFilter.class);

    private String filterProcessesUrl;

    private List<String> defaultRoles;

    /**
     * URL for Web SSO profile responses or unsolicited requests
     */
    public static final String FILTER_URL = "/accenture-sso/sso";

    public AccentureSsoProcessingFilter(String resourcePath) {
        this(FILTER_URL, resourcePath);
    }

    protected AccentureSsoProcessingFilter(String defaultFilterProcessesUrl, String resourcePath) {
        super(defaultFilterProcessesUrl);
        try {
            final Resource pemFile = new DefaultResourceLoader().getResource(resourcePath);
            this.documentBuilder = this.getDocumentBuilder();
            this.signatureValidator = this.getSignatureValidator(pemFile);
        } catch (Exception ex) {
            throw new RuntimeException("Could not initialize AccentureSsoProcessingFilter", ex);
        }
        setFilterProcessesUrl(defaultFilterProcessesUrl);
    }

    /**
     * In case the login attribute is not present it is presumed that the call is made from the remote IDP
     * and contains a SAML assertion which is processed and authenticated.
     *
     * @param request request
     * @return authentication object in case SAML data was found and valid
     * @throws AuthenticationException authentication failure
     */
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String assertion = request.getParameter("SAMLResponse");
        Assertion samlAssertion = this.extractAssertion(assertion);
        User user = this.extractUser(samlAssertion);
        Date expirationDate = this.getExpirationDate(samlAssertion);
        ExpiringUsernameAuthenticationToken result = new ExpiringUsernameAuthenticationToken(expirationDate, user, assertion, user.getAuthorities());
        result.setDetails(user);
        return result;
    }


    /**
     * Name of the profile this used for authentication.
     *
     * @return profile name
     */
    protected String getProfileName() {
        return SAMLConstants.SAML2_WEBSSO_PROFILE_URI;
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return SAMLUtil.processFilter(getFilterProcessesUrl(), request);
    }

    /**
     * Sets the URL used to determine if this Filter is invoked
     *
     * @param filterProcessesUrl the URL used to determine if this Filter is invoked
     */
    @Override
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
        super.setFilterProcessesUrl(filterProcessesUrl);
    }

    /**
     * Gets the URL used to determine if this Filter is invoked
     *
     * @return the URL used to determine if this Fitler is invoked
     */
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    private DocumentBuilder documentBuilder;

    private SignatureValidator signatureValidator;


    private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        return documentBuilderFactory.newDocumentBuilder();
    }

    private SignatureValidator getSignatureValidator(Resource pemFile) throws CertificateException, IOException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) fact.generateCertificate(pemFile.getInputStream());
        BasicX509Credential certificate = new BasicX509Credential();
        certificate.setEntityCertificate(cer);
        return new SignatureValidator(certificate);
    }

    private void logDocument(Document document) {
        try {
            DOMSource domSource = new DOMSource(document);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            tf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            tf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            logger.debug("SAML structure is: \n" + writer.toString());
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private Response parseXMLAssertion(Document document) throws UnmarshallingException {
        Element element = document.getDocumentElement();
        if (logger.isDebugEnabled()) {
            this.logDocument(document);
        }
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        return (Response) unmarshaller.unmarshall(element);
    }


    protected Date getExpirationDate(Assertion assertion) {
        DateTime expiration = null;
        for (AuthnStatement statement : assertion.getAuthnStatements()) {
            DateTime newExpiration = statement.getSessionNotOnOrAfter();
            if (newExpiration != null) {
                if (expiration == null || expiration.isAfter(newExpiration)) {
                    expiration = newExpiration;
                }
            }
        }
        return expiration != null ? expiration.toDate() : null;
    }

    private User extractUser(Assertion samlAssertion) {
        Set<String> groups = this.extractGroups(samlAssertion);
        List<GrantedAuthority> grantedAuthorities = groups.stream()
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());
        this.getDefaultRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role))
                .forEach(grantedAuthorities::add);
        NameID principal = samlAssertion.getSubject().getNameID();
        User user = new User(principal.getValue(), "", grantedAuthorities);
        return user;
    }

    private Assertion extractAssertion(String saml) {
        byte[] samlBytes = java.util.Base64.getDecoder().decode(saml);
        try (ByteArrayInputStream is = new ByteArrayInputStream(samlBytes)){
            Document document = documentBuilder.parse(is);
            Assertion samlAssertion = this.parseXMLAssertion(document).getAssertions().get(0);
            this.signatureValidator.validate(samlAssertion.getSignature());
            return samlAssertion;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Set<String> extractGroups(Assertion samlAssertion) {
        Set<String> result = new HashSet<>();
        List<Attribute> attributes = samlAssertion.getAttributeStatements().get(0).getAttributes();
        Attribute attribute = attributes.stream().filter(x -> x.getName().equals("http://schemas.xmlsoap.org/claims/Group")).findAny().orElse(null);
        for (XMLObject object : attribute.getAttributeValues()) {
            result.add(object.getDOM().getTextContent());
        }
        return result;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }

    public List<String> getDefaultRoles() {
        if (this.defaultRoles == null) {
            this.defaultRoles = new ArrayList<>();
        }
        return defaultRoles;
    }

    public void setDefaultRoles(List<String> defaultRoles) {
        this.defaultRoles = defaultRoles;
    }
}
