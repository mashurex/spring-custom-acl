package com.ashurex.springcustomacl.security.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

/**
 * Add JWT claims from the authentication user details.
 *
 * @author Mustafa Ashurex
 */
@Component
@Slf4j
public class CustomUserTokenEnhancer implements TokenEnhancer {

	public CustomUserTokenEnhancer() {
	}
	/**
	 * Enhance with standard and custom JWT claims from user details.
	 * See https://www.iana.org/assignments/jwt/jwt.xhtml for further info on standard claims.
	 *
	 * @param accessToken    Token to add additional claims to.
	 * @param authentication Authentication info to get claim information from.
	 *
	 * @return OAuth2AccessToken with add'l claim information from {@link OAuth2Authentication#getPrincipal()}
	 */
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		// This is where we can inject custom data into JWT tokens for use on future requests.
		// Ideally, whatever custom data we injected could be used to limit database queries to authorize
		// requests, etc.

		// ... implement any token enhancements or customizations ...

		return accessToken;
	}
}
