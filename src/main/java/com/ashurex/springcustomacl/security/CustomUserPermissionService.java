package com.ashurex.springcustomacl.security;

import java.util.List;
import com.ashurex.springcustomacl.security.acls.domain.MembershipPartyType;
import com.ashurex.springcustomacl.security.acls.domain.PartyMembership;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * @author Mustafa Ashurex
 */
@Service
@Slf4j
public class CustomUserPermissionService implements UserPermissionService, InitializingBean {
	private final PartyMembershipRepository partyMembershipRepository;
	private final Cache userPermissionsCache;

	@Autowired
	public CustomUserPermissionService(CacheManager cacheManager, PartyMembershipRepository partyMembershipRepository) {
		this.partyMembershipRepository = partyMembershipRepository;
		this.userPermissionsCache = cacheManager.getCache("userPermissions");
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		if (null == userPermissionsCache) {
			throw new IllegalStateException("Cannot find userPermissions cache");
		}
	}

	public List<PartyMembership> getUserPartyMemberships(@NonNull Authentication authentication) {
		return getUserPartyMemberships(authentication.getName());
	}

	public List<PartyMembership> getUserPartyMemberships(@NonNull Authentication authentication,
														 @NonNull MembershipPartyType type) {
		return getUserPartyMemberships(authentication.getName(), type);
	}

	public List<PartyMembership> getUserPartyMemberships(@NonNull String username) {
		return userPermissionsCache.get(username, () -> {
			log.trace("Fetching PartyMemberships for {}", username);
			return partyMembershipRepository.findAllForUsername(username);
		});
	}

	public List<PartyMembership> getUserPartyMemberships(@NonNull String username, @NonNull MembershipPartyType type) {
		return userPermissionsCache.get(username + "_" + type.name(), () -> {
			log.trace("Fetching {} PartyMemberships for {}", type.name(), username);
			return partyMembershipRepository.findAllOfPartyTypeForUsername(type, username);
		});
	}

	@Override
	public boolean hasFirmMembership(@NonNull String username, @NonNull Long firmId) {
		List<PartyMembership> firmMemberships = getUserPartyMemberships(username, MembershipPartyType.FIRM);
		boolean result = firmMemberships.stream().anyMatch(p -> {
			return p.getPartyId().equals(firmId);
		});

		if (!result && log.isTraceEnabled()) {
			log.trace("[UNAUTHORIZED] '{}' -> Firm: {}", username, firmId);
		}

		return result;
	}

	@Override
	public void refreshPermissions(String username) {
		for (MembershipPartyType type : MembershipPartyType.values()) {
			userPermissionsCache.evict(username + "_" + type.name());
		}
	}
}
