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

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter processes arriving SAML messages by delegating to the WebSSOProfile. After the SAMLAuthenticationToken
 * is obtained, authentication providers are asked to authenticate it.
 *
 * @author Vladimir Schäfer
 */
public class AccentureSsoRedirectFilter extends GenericFilterBean {

    private static Logger logger = LoggerFactory.getLogger(AccentureSsoRedirectFilter.class);

    private static final String SSO_LOGIN = "/accenture-sso/login";

    private static final String SSO_FILTER = "/accenture-sso/sso";

    private String idpUrl;

    private String rundeckUrl;

    public AccentureSsoRedirectFilter(String idpUrl, String rundeckUrl) {
        this.idpUrl = idpUrl;
        this.rundeckUrl = rundeckUrl;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        if (httpServletRequest.getRequestURI().contains(SSO_LOGIN)) {
            final String redirectUrl = idpUrl + "?relay=" + this.getRelayUrl(httpServletRequest.getRequestURL().toString());
            logger.debug("Redirecting to {}", idpUrl);
            httpServletResponse.sendRedirect(redirectUrl);
        } else {
            chain.doFilter(request, response);
        }
    }

    private String getRelayUrl(String contextPath) {
        final String prefix;
        if (Strings.isEmpty(rundeckUrl)) {
            prefix = contextPath;
        } else {
            prefix = rundeckUrl;
        }
        return StringUtils.replace(prefix, SSO_LOGIN, SSO_FILTER);
    }
}
