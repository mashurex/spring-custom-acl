package com.ashurex.springcustomacl.security.config;

import com.ashurex.springcustomacl.security.oauth2.RefreshTokenPreAuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * General MVC/Web security configuration, configures before the other security configurations/customizations.
 *
 * @author Mustafa Ashurex
 * @see AuthServerConfig
 * @see ResourceServerConfig
 * @see AclConfiguration
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private UserDetailsService userDetailsService;
	private PasswordEncoder passwordEncoder;
	private RefreshTokenPreAuthProvider refreshTokenPreAuthProvider;

	@Autowired
	public SecurityConfig(UserDetailsService userDetailsService,
						  PasswordEncoder passwordEncoder,
						  RefreshTokenPreAuthProvider refreshTokenPreAuthProvider) {
		super();
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
		this.refreshTokenPreAuthProvider = refreshTokenPreAuthProvider;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Use the autowired UserDetailsService and PasswordEncoder for the AuthenticationManager.
		//@formatter:off
		auth.userDetailsService(userDetailsService())
			.passwordEncoder(passwordEncoder)
			.and()
				.eraseCredentials(true)
			// This allows for auth token refreshing
			.authenticationProvider(refreshTokenPreAuthProvider);
		//@formatter:on
	}

	@Override
	@Bean
	// Expose this as the AuthenticationManager bean to be used throughout the system.
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//@formatter:off
        http.sessionManagement()
            // Stateless sessions because of JWT
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // Enable HTTP basic auth
            .httpBasic()
                .realmName("Demo API")
            .and()
            // Disable CSRF
            .csrf()
                .disable();
        //@formatter:on
	}

	@Override
	protected UserDetailsService userDetailsService() {
		// Return the autowired UserDetailsService so that all underlying methods that need it will use the provided one.
		return userDetailsService;
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		// Allow un-authenticated access to forgot password endpoint.
		web.ignoring().antMatchers("/api/forgot-password");
	}
}
