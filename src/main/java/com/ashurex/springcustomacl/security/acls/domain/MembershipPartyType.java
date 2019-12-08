package com.ashurex.springcustomacl.security.acls.domain;


import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentity;
import lombok.NonNull;
import org.springframework.security.acls.model.ObjectIdentity;

/**
 * Enumeration of party types eligible for party membership permission mapping.
 *
 * @author Mustafa Ashurex
 */
public enum MembershipPartyType {
	CLIENT,
	FIRM,
	DESK,
	STRATEGY,
	ACCOUNT;

	public static MembershipPartyType getMembershipPartyType(@NonNull ObjectIdentity oid) {
		if (oid instanceof PartyObjectIdentity) {
			return ((PartyObjectIdentity) oid).getPartyType();
		}

		return getMembershipPartyType(oid.getType());
	}

	/**
	 * @param objectType The canonical class name of the object to be inspected.
	 *
	 * @return The party type of the object.
	 *
	 * @throws IllegalArgumentException If {@literal objectType} isn't mapped to a member ship type.
	 */
	public static MembershipPartyType getMembershipPartyType(@NonNull String objectType) {
		String[] parts = objectType.split("\\.");
		String className = parts[parts.length - 1].toLowerCase();
		if (className.startsWith("firm")) {
			return MembershipPartyType.FIRM;
		}
		else if (className.startsWith("desk")) {
			return MembershipPartyType.DESK;
		}
		else if (className.startsWith("client")) {
			return MembershipPartyType.CLIENT;
		}
		else if (className.startsWith("strategy")) {
			return MembershipPartyType.STRATEGY;
		}
		else if (className.startsWith("account")) {
			return MembershipPartyType.ACCOUNT;
		}

		throw new IllegalArgumentException(objectType + " is not a valid membership type");
	}
}
