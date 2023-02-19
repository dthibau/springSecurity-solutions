package org.formation;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {


	
	@Bean
	public SecurityFilterChain restFilterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				  .antMatchers("/actuator/**").hasAuthority("SCOPE_MONITOR")
				  .anyRequest().hasAuthority("SCOPE_USER")
				  .and()
				  .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt).csrf().disable();
		

		return http.build();
	}
	

}
