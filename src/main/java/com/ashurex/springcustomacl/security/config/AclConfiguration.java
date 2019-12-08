package com.ashurex.springcustomacl.security.config;

import javax.sql.DataSource;
import com.ashurex.springcustomacl.security.JdbcPartyHierarchyService;
import com.ashurex.springcustomacl.security.PartyHierarchyService;
import com.ashurex.springcustomacl.security.PartyMembershipLookupStrategy;
import com.ashurex.springcustomacl.security.acls.PartyPermissionCacheOptimizer;
import com.ashurex.springcustomacl.security.acls.model.PartyMembershipAclService;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentityRetrievalStrategy;
import net.sf.ehcache.config.PersistenceConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentityGenerator;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * ACL and method security configuration and customization.
 *
 * @author Mustafa Ashurex
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AclConfiguration extends GlobalMethodSecurityConfiguration {
	private DataSource dataSource;

	@Autowired
	public AclConfiguration(DataSource dataSource) {
		this.dataSource = dataSource;
	}

	@Bean
	public EhCacheBasedAclCache aclCache(PermissionGrantingStrategy permissionGrantingStrategy) {
		// Spring ACL requires an ACL cache, and EhCache is the 'most supported' method.
		return new EhCacheBasedAclCache(aclEhCacheFactoryBean().getObject(),
										permissionGrantingStrategy,
										aclAuthorizationStrategy());
	}

	@Bean
	public EhCacheFactoryBean aclEhCacheFactoryBean() {
		// We might be stomping on current EhCache configuration, but this seems to work 🤷.
		EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();
		ehCacheFactoryBean.setCacheManager(aclCacheManager().getObject());
		ehCacheFactoryBean.setCacheName("aclCache");
		ehCacheFactoryBean.setTimeToLive(0);
		ehCacheFactoryBean.setTimeToIdle(0);
		PersistenceConfiguration pcfg = new PersistenceConfiguration();
		pcfg.setStrategy(PersistenceConfiguration.Strategy.LOCALTEMPSWAP.name());
		pcfg.setSynchronousWrites(false);
		ehCacheFactoryBean.addPersistence(pcfg);
		ehCacheFactoryBean.setDiskExpiryThreadIntervalSeconds(0);

		return ehCacheFactoryBean;
	}

	@Bean
	public EhCacheManagerFactoryBean aclCacheManager() {
		return new EhCacheManagerFactoryBean();
	}

	/**
	 * Provides ACL modification authorization rules to the ACL subsystem.
	 * <p>
	 * This allows the system to figure out what users/roles/privileges are authorized to make changes to ACL data,
	 * like users with ADMIN roles being able to grant other users access to Firms and Desks, etc.
	 *
	 * @return AclAuthorizationStrategy implementation.
	 */
	@Bean
	@Primary
	public AclAuthorizationStrategy aclAuthorizationStrategy() {
		// TODO: This will likely need customization for System > Client > Firm > Desk ACL mod privileges.
		return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_SYSADMIN"),
												new SimpleGrantedAuthority("ROLE_ADMIN"),
												new SimpleGrantedAuthority("ROLE_USER"));
	}

	/**
	 * This adds ACL permission evaluation into method permission evaluation such as
	 * {@code PreAuthorize} and {@code PostAuthorize}.
	 *
	 * @return MethodSecurityExpressionHandler configured for ACL evaluation.
	 */
	@Bean
	@Primary
	public MethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler(AclService aclService,
																				  PermissionFactory permissionFactory,
																				  RoleHierarchy roleHierarchy,
																				  ObjectIdentityRetrievalStrategy retrievalStrategy,
																				  ObjectIdentityGenerator objectIdentityGenerator) {
		DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		AclPermissionEvaluator permissionEvaluator = new AclPermissionEvaluator(aclService);
		permissionEvaluator.setObjectIdentityGenerator(objectIdentityGenerator);
		permissionEvaluator.setObjectIdentityRetrievalStrategy(retrievalStrategy);
		permissionEvaluator.setPermissionFactory(permissionFactory);
		expressionHandler.setPermissionEvaluator(permissionEvaluator);
		expressionHandler.setPermissionCacheOptimizer(new PartyPermissionCacheOptimizer(aclService, retrievalStrategy));
		expressionHandler.setRoleHierarchy(roleHierarchy);

		return expressionHandler;
	}

	@Bean
	@Primary
	public PartyMembershipLookupStrategy lookupStrategy(AclCache aclCache,
														PartyObjectIdentityRetrievalStrategy pidRetriever,
														PartyHierarchyService partyHierarchyService,
														AclAuthorizationStrategy aclAuthorizationStrategy,
														PermissionGrantingStrategy permissionGrantingStrategy,
														PermissionFactory permissionFactory) {
		return new PartyMembershipLookupStrategy(dataSource,
												 pidRetriever,
												 partyHierarchyService,
												 permissionFactory,
												 aclCache,
												 aclAuthorizationStrategy,
												 permissionGrantingStrategy);
	}

	@Bean
	@Primary
	public PartyMembershipAclService aclService(JdbcTemplate jdbcTemplate,
												LookupStrategy lookupStrategy,
												PartyHierarchyService partyHierarchyService) {
		return new PartyMembershipAclService(jdbcTemplate, lookupStrategy, partyHierarchyService);
	}

	@Bean
	@Primary
	public PartyObjectIdentityRetrievalStrategy partyObjectIdentityRetrievalStrategy() {
		return new PartyObjectIdentityRetrievalStrategy();
	}

	@Bean
	@Primary
	public PartyHierarchyService partyHierarchyService(JdbcTemplate jdbcTemplate,
													   PartyObjectIdentityRetrievalStrategy pidRetriever) {
		return new JdbcPartyHierarchyService(jdbcTemplate, pidRetriever);
	}
}
