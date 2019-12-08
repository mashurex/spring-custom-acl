package com.ashurex.springcustomacl.security.config;

import java.util.Arrays;
import com.ashurex.springcustomacl.security.oauth2.CustomUserTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * Configuration for the JWT/OAuth2 authorization server modules.
 * This configuration class enables the authentication sub-system to be used by {@link ResourceServerConfig}.
 * It could be possible to run the auth server completely separate/remote from the rest of this application.
 *
 * @author Mustafa Ashurex
 * @see ResourceServerConfig
 */
@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {
	private AuthenticationManager authenticationManager;
	private PasswordEncoder passwordEncoder;
	private JwtTokenStore tokenStore;
	private JwtAccessTokenConverter accessTokenConverter;
	private CustomUserTokenEnhancer customUserTokenEnhancer;
	private UserDetailsService userDetailsService;

	@Autowired
	public AuthServerConfig(@Qualifier("authenticationManagerBean") AuthenticationManager authenticationManager,
							PasswordEncoder passwordEncoder,
							JwtTokenStore tokenStore,
							JwtAccessTokenConverter accessTokenConverter,
							CustomUserTokenEnhancer customUserTokenEnhancer,
							UserDetailsService userDetailsService) {
		this.authenticationManager = authenticationManager;
		this.passwordEncoder = passwordEncoder;
		this.tokenStore = tokenStore;
		this.accessTokenConverter = accessTokenConverter;
		this.customUserTokenEnhancer = customUserTokenEnhancer;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
		// This is a sample single client configured in-memory to allow sign-in on behalf of users.
		configurer.inMemory()
				  .withClient("demoApiClient")
				  .secret(passwordEncoder.encode("password"))
				  .authorizedGrantTypes("implicit", "password", "authorization_code", "refresh_token")
				  // Allow the client to perform scoped actions, scopes can be completely customized as necessary.
				  .scopes("read", "write")
				  .and()
				  .build();
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(customUserTokenEnhancer, accessTokenConverter));
		endpoints.tokenStore(tokenStore)
				 .accessTokenConverter(accessTokenConverter)
				 .tokenEnhancer(enhancerChain)
				 .authenticationManager(authenticationManager)
				 // This allows for token refreshing from user details persistence.
				 .userDetailsService(userDetailsService)
				 .tokenServices(tokenServices());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		// Allow all unauthenticated sessions access to the token key endpoint (so they can authenticate).
		// Require authenticated sessions in order for them to check their token status.
		security.passwordEncoder(passwordEncoder)
				.tokenKeyAccess("permitAll()")
				.checkTokenAccess("permitAll()")
				.realm("Demo API");
	}

	@Bean
	@Primary
	public DefaultTokenServices tokenServices() throws Exception {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore);
		defaultTokenServices.setSupportRefreshToken(true);
		defaultTokenServices.setAuthenticationManager(authenticationManager);

		TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(customUserTokenEnhancer, accessTokenConverter));

		defaultTokenServices.setTokenEnhancer(enhancerChain);

		// Access token validity of 1 day
		defaultTokenServices.setAccessTokenValiditySeconds(86400);
		// Refresh token validity of 1 week
		defaultTokenServices.setRefreshTokenValiditySeconds(604800);
		defaultTokenServices.afterPropertiesSet();

		return defaultTokenServices;
	}
}
