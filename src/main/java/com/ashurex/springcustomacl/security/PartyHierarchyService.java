package com.ashurex.springcustomacl.security;

import java.util.List;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentity;

/**
 * Service interface for finding parent/child relationships of parties using Spring ACL {@link ObjectIdentity} values.
 *
 * @author Mustafa Ashurex
 * @see PartyMembershipLookupStrategy
 */
public interface PartyHierarchyService {
	/**
	 * Generate a {@link PartyObjectIdentity} for the given {@link ObjectIdentity}.
	 *
	 * @param id The {@code ObjectIdentity} to generate a PID for.
	 *
	 * @return A {@code PartyObjectIdentity} generated or the given {@code ObjectIdentity}.
	 */
	PartyObjectIdentity getPartyIdentity(ObjectIdentity id);

	/**
	 * Find all distinct parent {@code PartyObjectIdentity} values for the given {@code ObjectIdentity}.
	 *
	 * @param id The OID to find parent PIDs for.
	 *
	 * @return A {@code List} of distinct parent {@link PartyObjectIdentity} values for the given
	 * {@link ObjectIdentity}.
	 */
	List<PartyObjectIdentity> getAncestors(ObjectIdentity id);

	/**
	 * Find all distinct child {@code PartyObjectIdentity} values for the given {@code ObjectIdentity}.
	 *
	 * @param id The OID to find child PIDs for.
	 *
	 * @return A {@code List} of distinct child {@link PartyObjectIdentity} values for the given
	 * {@link ObjectIdentity}.
	 */
	List<PartyObjectIdentity> getPredecessors(ObjectIdentity id);
}
