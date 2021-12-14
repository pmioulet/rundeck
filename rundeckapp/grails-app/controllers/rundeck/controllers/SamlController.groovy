package rundeck.controllers
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

class SamlController extends ControllerBase{
	def MetadataManager metadata

	def discovery() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication()
		if (auth == null)
			log.debug("Current authentication instance from security context is null")
		else
			log.debug("Current authentication instance from security context: " + this.getClass().getSimpleName())
		if (auth == null || (auth instanceof AnonymousAuthenticationToken)) {
			Set<String> idps = metadata.getIDPEntityNames()
			for (String idp : idps){
				log.info("Configured Identity Provider for SSO: " + idp)
            }
			//model.addAttribute("idps", idps)
			return "pages/discovery"
		} else {
			log.warn("The current user is already logged.")
			return "redirect:/landing"
		}
	}

}