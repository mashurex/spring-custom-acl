package com.ashurex.springcustomacl.security.acls.model;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import com.ashurex.springcustomacl.security.PartyHierarchyService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

/**
 * @author Mustafa Ashurex
 */
public class PartyMembershipAclService implements AclService {
	// TODO: This could implement MutableAclService as well, with some work.

	private final LookupStrategy lookupStrategy;
	private final JdbcTemplate jdbcTemplate;
	private final PartyHierarchyService partyHierarchyService;

	public PartyMembershipAclService(JdbcTemplate jdbcTemplate,
									 LookupStrategy lookupStrategy,
									 PartyHierarchyService partyHierarchyService) {
		this.lookupStrategy = lookupStrategy;
		this.jdbcTemplate = jdbcTemplate;
		this.partyHierarchyService = partyHierarchyService;
	}

	@Override
	public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
		return partyHierarchyService.getPredecessors(parentIdentity)
									.stream()
									.map(m -> (ObjectIdentity) m)
									.collect(Collectors.toList());
	}

	@Override
	public Acl readAclById(ObjectIdentity object) throws NotFoundException {
		return readAclById(object, null);
	}

	@Override
	public Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Arrays.asList(object), sids);
		// The default implementation did not have this check, but if we stop throwing an NFE in the
		// readAclsById(List<ObjectIdentity> objects, List<Sid> sids) method, we will need to perform the check here.
		// Returning a null will cause NPE downstream. Optionally, we could return an 'empty' DENY ACL or some sort,
		// but the code that calls this gracefully handles an NFE.
		//        if (!map.containsKey(object)) {
		//            throw new NotFoundException("Cannot find ACL for ObjectIdentity " + object);
		//        }
		return map.get(object);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException {
		return readAclsById(objects, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids)
			throws NotFoundException {
		Map<ObjectIdentity, Acl> result = lookupStrategy.readAclsById(objects, sids);

		// Check every requested object identity was found (throw NotFoundException if needed)
		for (ObjectIdentity oid : objects) {
			if (!result.containsKey(oid)) {
				throw new NotFoundException("Unable to find ACL information for object identity '" + oid + "'");
			}
		}

		return result;
	}
}
