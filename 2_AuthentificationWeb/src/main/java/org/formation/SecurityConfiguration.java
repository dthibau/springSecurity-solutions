package org.formation;

import java.util.Locale;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
<<<<<<< HEAD
import org.springframework.security.config.Customizer;
=======
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
>>>>>>> 7d6c542 (Thymeleaf et localisation)
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> {
			auth.requestMatchers("/fournisseurs*").hasRole("MANAGER")
					.requestMatchers("/produits*").hasAnyRole("PRODUCT_MANAGER", "MANAGER")
					.requestMatchers("/swagger-ui.html", "/swagger-resources/**", "/v2/api-docs/**").permitAll()
					.requestMatchers("/api/*").permitAll()
					.requestMatchers("/actuator/**").permitAll()
					.anyRequest().authenticated();
		})
			.formLogin(Customizer.withDefaults())
				.sessionManagement(sm -> sm.maximumSessions(2))
				.logout(lo -> lo.invalidateHttpSession(true).logoutSuccessUrl("http://www.plb.fr"))
				.csrf(csrf -> csrf.disable());

		return http.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers("/resources/**", "/publics/**","/webjars/*");
	}

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public MessageSource messageSource() {
		Locale.setDefault(Locale.FRENCH);
		ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
		messageSource.addBasenames("classpath:org/springframework/security/messages");
		return messageSource;
	}
}
