package rundeck.services.authorization;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    private static final String ROLE_NAME = "Role";

    @Autowired
    public SAMLUserDetailsServiceImpl() {
    }

    public Object loadUserBySAML(SAMLCredential credential)
            throws UsernameNotFoundException {
        List<GrantedAuthority> grantedAuthorities = credential.getAttributes().stream()
                .filter(attribute -> attribute.getName().equals(ROLE_NAME))
                .map(attribute -> getAttributeValue(attribute.getAttributeValues().get(0)))
                .map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
        String username = credential.getNameID().getValue();
        String password = "";
        User result = new User(username, password, grantedAuthorities);
        LOG.info("Granted {} to {}", grantedAuthorities, username);
        return result;
    }


    private String getAttributeValue(XMLObject attributeValue) {
        return attributeValue == null ?
                null :
                attributeValue instanceof XSString ?
                        getStringAttributeValue((XSString) attributeValue) :
                        attributeValue instanceof XSAnyImpl ?
                                getAnyAttributeValue((XSAnyImpl) attributeValue) :
                                attributeValue.toString();
    }

    private String getStringAttributeValue(XSString attributeValue) {
        return attributeValue.getValue();
    }

    private String getAnyAttributeValue(XSAnyImpl attributeValue) {
        return attributeValue.getTextContent();
    }
}
