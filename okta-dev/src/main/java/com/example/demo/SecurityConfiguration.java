package com.example.demo;

import java.io.File;

import javax.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;

import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
	
//	@Autowired
//    private SamlServerConfiguration samlServerConfiguration;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
	    	.authorizeRequests(authorize -> 
	    		authorize.antMatchers("/").permitAll().anyRequest().authenticated()
	        ).saml2Login();
		// add auto-generation of ServiceProvider Metadata
		Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
		Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());
		http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
	}
	
	
//	@Override
//    protected void configure(final ServiceProviderConfigurer configurer) throws Exception {
//        configurer
//                .metadataGenerator()
//                    .entityId("your-entity-id")
//                    .entityBaseURL("http://localhost:8080")
//                    .signMetadata(true)
//                    .and()
//                .rotatingKeys()
//                    .use(null)
//                    .and()
//                .sso()
//                    .defaultSuccessURL("/home")
//                    .and()
//                .logout()
//                    .defaultTargetURL("/")
//                    .and()
//                .metadataManager()
//                    .refreshCheckInterval(0)
//                    .provider(samlServerConfiguration)
//                    .and()
//                .extendedMetadata()
//                    .signMetadata(true)
//                    .and()
//                .keyManager();
//    }
	
	
	@Bean
	protected RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File verificationKey = new File("d:\\projects\\okta-cams.cert");
	    java.security.cert.X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
	    Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
	    RelyingPartyRegistration registration = RelyingPartyRegistration
	            .withRegistrationId("okta")
	            .assertingPartyDetails(party -> party
	                .entityId("http://www.okta.com/exk6i1y75kIMnWzYe697")
	                .singleSignOnServiceLocation("https://securelogin.motherson.com/app/mothersongroup_mtslcams_1/exk6i1y75kIMnWzYe697/sso/saml")
	                .wantAuthnRequestsSigned(false)
	                .verificationX509Credentials(c -> c.add(credential))
	            ).build();
	    return new InMemoryRelyingPartyRegistrationRepository(registration);
	}
}
