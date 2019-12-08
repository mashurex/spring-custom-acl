package com.ashurex.springcustomacl.security.acls;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

/**
 * Implementation of {@link PermissionCacheOptimizer} that is basically a 'safer' version of
 * {@link org.springframework.security.acls.AclPermissionCacheOptimizer}.
 *
 * @author Mustafa Ashurex
 * @see PermissionCacheOptimizer
 * @see org.springframework.security.acls.AclPermissionCacheOptimizer
 */
@Slf4j
public class PartyPermissionCacheOptimizer implements PermissionCacheOptimizer {
	private final AclService aclService;
	private final ObjectIdentityRetrievalStrategy oidRetrievalStrategy;
	private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();

	public PartyPermissionCacheOptimizer(AclService aclService, ObjectIdentityRetrievalStrategy oidRetrievalStrategy) {
		this.aclService = aclService;
		this.oidRetrievalStrategy = oidRetrievalStrategy;
	}

	@Override
	public void cachePermissionsFor(Authentication authentication, Collection<?> objects) {
		if (null == objects || objects.isEmpty()) {
			return;
		}

		List<ObjectIdentity> oidsToCache = new ArrayList<>(objects.size());

		for (Object domainObject : objects) {
			if (domainObject == null) {
				continue;
			}
			try {
				ObjectIdentity oid = oidRetrievalStrategy.getObjectIdentity(domainObject);
				if (null != oid) {
					oidsToCache.add(oid);
				}
			}
			catch (Exception ex) {
				log.warn("Could not get ObjectIdentity for domainObject " + domainObject.getClass().getName(), ex);
			}
		}

		List<Sid> sids = Collections.emptyList();
		// Safely try and retrieve SIDs for this authentication session.
		if (null != authentication) {
			try {
				sids = sidRetrievalStrategy.getSids(authentication);
			}
			catch (Exception ex) {
				log.warn(ex.getMessage(), ex.getCause());
			}
		}

		if (log.isTraceEnabled()) {
			log.trace("Eagerly loading Acls for " + oidsToCache.size() + " objects");
		}

		try {
			aclService.readAclsById(oidsToCache, sids);
		}
		catch (NotFoundException ex) {
			// It's okay for NFEs to be thrown since we're just priming the cache.
			log.debug(ex.getMessage());
		}
		catch (Exception ex) {
			// For now, we don't want exceptions in the cache optimizer to blow anything else up.
			// At some point we may want to let certain exceptions through.
			log.error(ex.getMessage(), ex.getCause());
		}
	}

	public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
		this.sidRetrievalStrategy = sidRetrievalStrategy;
	}
}
