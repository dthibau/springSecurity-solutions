package org.formation;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Locale;

import org.formation.jwt.JWTFilter;
import org.formation.jwt.TokenProvider;
import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

	@Autowired
	TokenProvider tokenProvider;
	@Value("${spring.security.saml2.relyingparty.registration.product-app.assertingparty.metadata-uri}")
	private String metadataLocation;
	@Value("${spring.security.saml2.relyingparty.registration.product-app.signing.credentials[0].certificate-location}")
	private String rpSigningCertLocation;

	@Value("${spring.security.saml2.relyingparty.registration.product-app.signing.credentials[0].private-key-location}")
	private String rpSigningKeyLocation;

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
			.saml2Login(Customizer.withDefaults())
				.saml2Logout(Customizer.withDefaults())
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
