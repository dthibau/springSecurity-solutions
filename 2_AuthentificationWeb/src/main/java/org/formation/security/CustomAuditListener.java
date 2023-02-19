package org.formation.security;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.security.AbstractAuthorizationAuditListener;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;

@Component
public class CustomAuditListener extends AbstractAuthorizationAuditListener {

		  
	 
	    public static final String AUTHORIZATION_FAILURE 
	      = "AUTHORIZATION_FAILURE";
	 

	 
	    private void onAuthorizationFailureEvent(
	      AuthorizationFailureEvent event) {
	        Map<String, Object> data = new HashMap<>();
	        data.put(
	          "type", event.getAccessDeniedException().getClass().getName());
	        data.put("message", event.getAccessDeniedException().getMessage());
	        data.put(
	          "requestUrl", ((FilterInvocation)event.getSource()).getRequestUrl() );
	         
	        if (event.getAuthentication().getDetails() != null) {
	            data.put("details", 
	              event.getAuthentication().getDetails());
	        }
	        publish(new AuditEvent(event.getAuthentication().getName(), 
	          AUTHORIZATION_FAILURE, data));
	    }

	@Override
	public void onApplicationEvent(AuthorizationEvent event) {
	}
}
