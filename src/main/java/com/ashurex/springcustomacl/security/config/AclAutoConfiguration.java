package com.ashurex.springcustomacl.security.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.ashurex.springcustomacl.security.acls.domain.CustomPermission;
import com.ashurex.springcustomacl.security.acls.domain.CustomPermissionGrantingStrategy;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.security.oauth2.OAuth2AutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.OAuth2AuthorizationServerConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2RestOperationsConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.method.OAuth2MethodSecurityConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyAuthoritiesMapper;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyUtils;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * This auto-configuration class is meant to mimic OAuth2AutoConfiguration but it skips the
 * OAuth2MethodSecurityConfiguration configuration import because it winds up overriding the
 * ACL permission method evaluator.
 *
 * @author Mustafa Ashurex
 * @see OAuth2AutoConfiguration
 * @see OAuth2MethodSecurityConfiguration
 * @see AclConfiguration
 */
@Configuration
@ConditionalOnClass({OAuth2AccessToken.class, WebMvcConfigurerAdapter.class, AclPermissionEvaluator.class})
@AutoConfigureBefore({WebMvcAutoConfiguration.class, OAuth2AutoConfiguration.class})
@Import({AclConfiguration.class,
		 OAuth2AuthorizationServerConfiguration.class,
		 OAuth2ResourceServerConfiguration.class,
		 OAuth2RestOperationsConfiguration.class})
@EnableConfigurationProperties({OAuth2ClientProperties.class, SecurityJwtConfigProperties.class})
public class AclAutoConfiguration {
	private final OAuth2ClientProperties credentials;
	private final SecurityJwtConfigProperties jwtProperties;

	public AclAutoConfiguration(OAuth2ClientProperties credentials, SecurityJwtConfigProperties jwtProperties) {
		this.credentials = credentials;
		this.jwtProperties = jwtProperties;
	}

	@Bean
	@Primary
	public org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties resourceServerProperties() {
		return new org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties(this.credentials
																													.getClientId(),
																											this.credentials
																													.getClientSecret());
	}

	@Bean
	@Primary
	public PermissionGrantingStrategy permissionGrantingStrategy() {
		// Ensure the usage of our custom ACL permission granting strategy.
		return new CustomPermissionGrantingStrategy(new ConsoleAuditLogger());
	}

	@Bean
	@Primary
	public PermissionFactory permissionFactory() {
		// Set the permission factory to use our custom Permission class.
		return new DefaultPermissionFactory(CustomPermission.class);
	}

	@Bean
	@Primary
	public RoleHierarchy roleHierarchy() {
		Map<String, List<String>> hierarchyMap = new HashMap<>();

		// ... custom code for defining role hierarchies (as necessary) ...

		RoleHierarchyImpl rh = new RoleHierarchyImpl();
		rh.setHierarchy(RoleHierarchyUtils.roleHierarchyFromMap(hierarchyMap));
		return rh;
	}

	@Bean
	@Primary
	public GrantedAuthoritiesMapper roleHierarchyAuthoritiesMapper(RoleHierarchy roleHierarchy) {
		// Publish the hierarchy as the default granted authorities mapper.
		return new RoleHierarchyAuthoritiesMapper(roleHierarchy);
	}

	@Bean
	@Primary
	public RoleHierarchyVoter hierarchyRoleVoter(RoleHierarchy roleHierarchy) {
		return new RoleHierarchyVoter(roleHierarchy);
	}

	@Bean
	@Primary
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setSigningKey(jwtProperties.getSigningKey());
		return converter;
	}

	@Bean
	@Primary
	public JwtTokenStore tokenStore(JwtAccessTokenConverter converter) {
		return new JwtTokenStore(converter);
	}
}
