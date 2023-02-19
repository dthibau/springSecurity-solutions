package org.formation.controller.rest;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserInfoRestController {

	
	@GetMapping("/user-info")
	public Authentication userInfo(Authentication authentication) {
		return authentication;
	}
}
