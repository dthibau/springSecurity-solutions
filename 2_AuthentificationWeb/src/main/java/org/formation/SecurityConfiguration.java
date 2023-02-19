package org.formation;

import java.util.Locale;

import org.formation.jwt.JWTFilter;
import org.formation.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

	@Autowired
	TokenProvider tokenProvider;
	
	@Bean
	public SecurityFilterChain restFilterChain(HttpSecurity http) throws Exception {
		http.securityMatcher(new AntPathRequestMatcher("/api/**"))
			.authorizeHttpRequests(auth -> auth.requestMatchers("/api/authenticate").permitAll()
					.anyRequest().authenticated())
			.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		        .addFilterBefore(new JWTFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class)
		        .csrf(csrf -> csrf.disable());


		return http.build();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		/*http.authorizeHttpRequests(auth -> {
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
				.csrf(csrf -> csrf.disable());*/


		http.securityMatcher(new RegexRequestMatcher("^((?!/api).)*$", null))
						.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.formLogin(Customizer.withDefaults());

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
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	    return authenticationConfiguration.getAuthenticationManager();
	}
	@Bean
	public MessageSource messageSource() {
		Locale.setDefault(Locale.FRENCH);
		ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
		messageSource.addBasenames("classpath:org/springframework/security/messages");
		return messageSource;
	}
}
