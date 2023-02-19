package org.formation.controller.mvc;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/sessions")
public class SessionController {

	@Autowired
	SessionRegistry sessionRegistry;
	
	@GetMapping
	public String getAllSessions(Model model) {
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		
		List<SessionInformation> sessions = sessionRegistry.getAllSessions(auth.getPrincipal(), false);
		model.addAttribute("sessions", sessions);
	
		return "sessions";
	}
}