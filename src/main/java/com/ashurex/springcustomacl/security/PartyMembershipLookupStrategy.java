package com.ashurex.springcustomacl.security;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import com.ashurex.springcustomacl.security.acls.domain.CustomPermission;
import com.ashurex.springcustomacl.security.acls.domain.MembershipPartyType;
import com.ashurex.springcustomacl.security.acls.domain.PartyMembership;
import com.ashurex.springcustomacl.security.acls.model.PartyMembershipAcl;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentity;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentityRetrievalStrategy;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;


/**
 * Implementation of {@link LookupStrategy} using a custom party membership table along with a user data table instead
 * of the default spring ACL tables so we don't have to create so many redundant entries.
 *
 * @author Mustafa Ashurex
 */
@Slf4j
public class PartyMembershipLookupStrategy implements LookupStrategy {

	private final JdbcTemplate jdbcTemplate;
	private final AclCache aclCache;
	private final PermissionFactory permissionFactory;
	private final AclAuthorizationStrategy aclAuthorizationStrategy;
	private final PermissionGrantingStrategy permissionGrantingStrategy;
	private final PartyObjectIdentityRetrievalStrategy partyIdRetriever;
	private final PartyHierarchyService partyHierarchyService;

	@Setter
	@Getter
	private int batchSize = 100;

	public PartyMembershipLookupStrategy(DataSource dataSource,
										 PartyObjectIdentityRetrievalStrategy partyIdRetriever,
										 PartyHierarchyService partyHierarchyService,
										 PermissionFactory permissionFactory,
										 AclCache aclCache,
										 AclAuthorizationStrategy aclAuthorizationStrategy,
										 PermissionGrantingStrategy permissionGrantingStrategy) {
		this.jdbcTemplate = new JdbcTemplate(dataSource);
		this.permissionFactory = permissionFactory;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
		this.permissionGrantingStrategy = permissionGrantingStrategy;
		this.aclCache = aclCache;
		this.partyIdRetriever = partyIdRetriever;
		this.partyHierarchyService = partyHierarchyService;
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) {
		final Map<ObjectIdentity, Acl> result = new HashMap<>();
		final Set<ObjectIdentity> currentBatchToLoad = new HashSet<>();

		for (int i = 0; i < objects.size(); i++) {
			ObjectIdentity oid = objects.get(i);
			if (null == oid) {
				continue;
			}

			boolean aclFound = false;

			if (result.containsKey(oid)) {
				aclFound = true;
			}

			if (!aclFound) {
				try {
					Acl acl = aclCache.getFromCache(oid);
					if (acl != null) {
						if (acl.isSidLoaded(sids)) {
							result.put(acl.getObjectIdentity(), acl);
							aclFound = true;
						}
						else if (acl instanceof PartyMembershipAcl) {
							// TODO: SIDs aren't being loaded
							loadInheritedAceEntries((PartyMembershipAcl) acl, sids);
						}
					}
				}
				catch (IllegalArgumentException | IllegalStateException ex) {
					log.warn("Error finding ObjectIdentity: {}", ex.getMessage(), ex.getCause());
				}
			}

			if (!aclFound) {
				currentBatchToLoad.add(oid);
			}

			if ((currentBatchToLoad.size() == this.batchSize) || ((i + 1) == objects.size())) {
				if (currentBatchToLoad.size() > 0) {
					Map<ObjectIdentity, PartyMembershipAcl> loadedBatch = lookupObjectIdentities(currentBatchToLoad,
																								 sids);

					// Add loaded batch (all elements 100% initialized) to results
					result.putAll(loadedBatch);

					// Add the loaded batch to the cache
					for (PartyMembershipAcl loadedAcl : loadedBatch.values()) {
						aclCache.putInCache(loadedAcl);
					}

					currentBatchToLoad.clear();
				}
			}
		}

		return result;
	}

	private PartyObjectIdentity getPartyIdentity(ObjectIdentity oid) {
		if (null == oid) {
			throw new NullPointerException("ObjectIdentity cannot be null");
		}

		if (oid instanceof PartyObjectIdentity) {
			return (PartyObjectIdentity) oid;
		}

		return partyIdRetriever.createObjectIdentity(oid.getIdentifier(), oid.getType());
	}

	private List<PartyMembership> getPartyMemberships(Collection<? extends ObjectIdentity> objectIdentities,
													  Collection<PrincipalSid> principals) {


		// Query for all the party membership entries, given the filter criteria.
		return Collections.emptyList();

		// An implementation would look something like this:
		// return jdbcTemplate.query(sql, params, new PartyMembershipResultSetExtractor(permissionFactory));
	}

	/**
	 * Populate the given ACL with ACEs that are either explicitly defined (PartyMembership entries exist) or are
	 * implicitly defined via inheritance from a parent ACL/PartyMembership entry.
	 *
	 * @param acl  The ACL to populate with ACE entries via hierarchical inheritance.
	 * @param sids If null, _ALL_ ACEs will be loaded, otherwise just for the given SIDs.
	 */
	private void loadInheritedAceEntries(final PartyMembershipAcl acl, Collection<Sid> sids) {
		PartyObjectIdentity pid = getPartyIdentity(acl.getObjectIdentity());
		// If we're at FIRM or CLIENT level we don't need to inherit
		if (pid.getPartyType() == MembershipPartyType.FIRM || pid.getPartyType() == MembershipPartyType.CLIENT) {
			return;
		}

		List<PrincipalSid> principals = null;
		//        TODO: Not currently implemented, as we currently just load everything at once for now.
		//        if (null != sids) {
		//            principals = sids.stream()
		//                             .filter(s -> s instanceof PrincipalSid)
		//                             .map(s -> (PrincipalSid) s)
		//                             .distinct()
		//                             .collect(Collectors.toList());
		//            if (principals.isEmpty()) {
		//                return;
		//            }
		//        }

		List<PartyObjectIdentity> parents = partyHierarchyService.getAncestors(pid);
		if (parents.isEmpty()) {
			return;
		}

		log.debug("Loading inherited ACE entries for {}", acl.getObjectIdentity().getIdentifier());

		// For each parent PartyMembership entry that has isInheriting = true, we want to create an ACE for this ACL
		final List<PartyMembership> parentMemberships = getPartyMemberships(parents, principals);
		parentMemberships.stream().filter(PartyMembership::isInheriting).forEach(m -> {
			PrincipalSid sid = m.getPrincipalSid();
			AccessControlEntryImpl ace = new AccessControlEntryImpl(m.getId(), acl, sid, m, true, false, false);
			AccessControlEntryImpl existing = acl.getEntries()
												 .stream()
												 .filter(e -> e.getSid().equals(sid))
												 .map(e -> (AccessControlEntryImpl) e)
												 .findFirst()
												 .orElse(null);
			// We only want one ACE per user per ACL
			if (null == existing) {
				log.debug("Creating new inherited ACE for {}:{} {}",
						  acl.getObjectIdentity().getIdentifier(),
						  sid.getPrincipal(),
						  ace.getPermission());
				acl.addAce(ace);
			}
			else if (ace.getPermission().getMask() != existing.getPermission().getMask()) {
				// Combine the permissions for now (they should always be equal in reality).
				int combinedPermissionMask = ace.getPermission().getMask() | existing.getPermission().getMask();
				if (combinedPermissionMask != existing.getPermission().getMask()) {
					final Permission newPermission = new CustomPermission(combinedPermissionMask);
					int index = acl.getEntries().indexOf(existing);
					acl.updateAce(index, newPermission);
					log.info("Updating ACE entry with inheritance for {}:{} from {} to {}",
							 acl.getObjectIdentity().getIdentifier(),
							 sid.getPrincipal(),
							 existing.getPermission(),
							 newPermission);
				}
			}
		});
	}

	private Map<ObjectIdentity, PartyMembershipAcl> lookupObjectIdentities(final Collection<ObjectIdentity> objectIdentities,
																		   Collection<Sid> sids) {
		if (log.isTraceEnabled()) {
			log.debug("Querying for {} ObjectIdentities: {}",
					  objectIdentities.size(),
					  StringUtils.join(objectIdentities.toArray(), ','));
		}

		final Map<String, PartyMembershipAcl> acls = new HashMap<>();
		for (ObjectIdentity oid : objectIdentities) {
			PartyObjectIdentity pid = new PartyObjectIdentity(oid);
			acls.computeIfAbsent(pid.getPartyCode(), partyCode -> {
				log.debug("Building new ACL for {}", pid);
				PartyMembershipAcl acl = new PartyMembershipAcl(partyCode,
																pid,
																false,
																null,
																aclAuthorizationStrategy,
																permissionGrantingStrategy,
																null);
				// Load all inherited ACEs before continuing on to explicit entries.
				// The inherited ACE entries will be overwritten with any explicit PartyMembership entries
				// found in the following lines of code.
				loadInheritedAceEntries(acl, null);
				return acl;
			});
		}

		final List<PartyMembership> memberships = getPartyMemberships(objectIdentities, null);

		// For each party membership, create an ACL for each unique OID and fill them with an ACE for every
		// PartyMembership in the list.
		for (PartyMembership m : memberships) {
			PartyMembershipAcl acl = acls.get(m.getPartyCode());
			// Create an ACE for the party's ACL entry.
			PrincipalSid sid = m.getPrincipalSid();
			AccessControlEntryImpl ace = new AccessControlEntryImpl(m.getId(), acl, sid, m, true, false, false);
			AccessControlEntryImpl existing = acl.getEntries()
												 .stream()
												 .filter(e -> e.getSid().equals(sid))
												 .map(e -> (AccessControlEntryImpl) e)
												 .findFirst()
												 .orElse(null);
			if (null == existing) {
				if (log.isDebugEnabled() && m.getPartyType() != MembershipPartyType.FIRM) {
					log.debug("Could not find existing ACE for {}:{}, adding new permission {}",
							  acl.getObjectIdentity().getIdentifier(),
							  sid.getPrincipal(),
							  ace.getPermission());
				}
				acl.addAce(ace);
			}
			else {
				// Replace an inherited ACEs with any directly assigned.
				log.debug("Replacing ACE entry for {}:{} from {} to {}",
						  acl.getObjectIdentity().getIdentifier(),
						  sid.getPrincipal(),
						  existing.getPermission(),
						  ace.getPermission());
				int index = acl.getEntries().indexOf(existing);
				acl.deleteAce(index);
				acl.addAce(ace);
			}
		}

		Map<ObjectIdentity, PartyMembershipAcl> resultMap = new HashMap<>();
		for (PartyMembershipAcl a : acls.values()) {
			resultMap.put(a.getObjectIdentity(), a);
		}

		return resultMap;
	}
}
