package com.ashurex.springcustomacl.security.oauth2;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.stereotype.Component;

/**
 * This component gets wired in to AuthenticationManager instances so that pre authenticated tokens can be turned in to
 * UserDetails and authenticated for requests that provide a JWT/OAuth token.
 *
 * @author Mustafa Ashurex
 */
@Component
public class RefreshTokenPreAuthProvider extends PreAuthenticatedAuthenticationProvider implements InitializingBean {

	private TokenGrantedAuthoritiesUserDetailsService userService;

	@Autowired
	public RefreshTokenPreAuthProvider(TokenGrantedAuthoritiesUserDetailsService userService) {
		super();
		this.userService = userService;
	}

	@Override
	public void afterPropertiesSet() {
		super.setPreAuthenticatedUserDetailsService(userService);
	}
}
