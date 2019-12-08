package com.ashurex.springcustomacl.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * Oauth/JWT resource authentication configuration, which depends on {@link AuthServerConfig} to provide
 * the facilities to authorize OAuth/JWT tokens.
 * <p>
 * {@link #configure(ResourceServerSecurityConfigurer)} will need to be implemented if the resource server is
 * disconnected from the auth server.
 *
 * @author Mustafa Ashurex
 * @see AuthServerConfig
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	private final ResourceServerTokenServices tokenServices;
	private final JwtTokenStore jwtTokenStore;

	@Autowired
	public ResourceServerConfig(ResourceServerTokenServices tokenServices, JwtTokenStore jwtTokenStore) {
		this.tokenServices = tokenServices;
		this.jwtTokenStore = jwtTokenStore;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// Enable authentication checks on the /api
		http.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.requestMatchers()
			.and()
			.authorizeRequests()
			.antMatchers("/api/**")
			.authenticated()
			.and()
			.csrf()
			.disable()
			.authorizeRequests();
	}

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenServices(tokenServices)
				 .tokenStore(jwtTokenStore)
				 .stateless(true);
	}
}
