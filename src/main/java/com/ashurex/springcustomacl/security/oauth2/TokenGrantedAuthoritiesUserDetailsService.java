package com.ashurex.springcustomacl.security.oauth2;


import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 * This component allows the lookup of UserDetails from OAuth/JWT tokens using a standard UserDetailsService so that
 * token refreshes and such can be accepted.
 *
 * @author Mustafa Ashurex
 */
@Component
public class TokenGrantedAuthoritiesUserDetailsService
		implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
	private final UserDetailsService userDetailsService;

	@Autowired
	public TokenGrantedAuthoritiesUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public UserDetails loadUserDetails(@NonNull PreAuthenticatedAuthenticationToken token)
			throws UsernameNotFoundException {
		Object principal = token.getPrincipal();
		if (principal instanceof UserDetails) {
			return (UserDetails) principal;
		}
		else {
			return userDetailsService.loadUserByUsername(token.getName());
		}
	}
}
