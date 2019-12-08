package com.ashurex.springcustomacl.security.acls.model;

import java.io.Serializable;
import com.ashurex.springcustomacl.security.acls.domain.MembershipPartyType;
import com.ashurex.springcustomacl.security.acls.domain.PartyMembership;
import lombok.NonNull;
import org.springframework.security.acls.model.ObjectIdentity;

/**
 * Implementation of {@link ObjectIdentity} that uses party codes (e.g. shortName) as the identity value.
 *
 * @author Mustafa Ashurex
 * @see MembershipPartyType
 */
public class PartyObjectIdentity implements ObjectIdentity {
	private final MembershipPartyType partyType;
	private final String partyCode;

	/**
	 * Instantiate an identity from a {@link PartyMembership} entry.
	 *
	 * @param m The entry to create an identity from.
	 *
	 * @see #PartyObjectIdentity(MembershipPartyType, String)
	 */
	public PartyObjectIdentity(@NonNull PartyMembership m) {
		this(m.getPartyType(), m.getPartyCode());
	}

	/**
	 * @param partyType The party type this identity is for.
	 * @param code      The party code/short name to use as the identity value.
	 */
	public PartyObjectIdentity(@NonNull MembershipPartyType partyType, @NonNull String code) {
		this.partyType = partyType;
		this.partyCode = code;
	}

	public PartyObjectIdentity(@NonNull ObjectIdentity oid) {
		this(MembershipPartyType.getMembershipPartyType(oid), oid.getIdentifier().toString());
	}

	public MembershipPartyType getPartyType() {
		return partyType;
	}

	public String getPartyCode() {
		return partyCode;
	}

	@Override
	public Serializable getIdentifier() {
		return partyCode;
	}

	@Override
	public String getType() {
		return partyType.name();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}

		if (!(o instanceof ObjectIdentity)) {
			return false;
		}

		if (!getType().equalsIgnoreCase(((ObjectIdentity) o).getType())) {
			return false;
		}

		return getIdentifier().equals(((ObjectIdentity) o).getIdentifier());
	}

	@Override
	public int hashCode() {
		int result = getType() != null ? getType().hashCode() : 0;
		result = 31 * result + (getIdentifier() != null ? getIdentifier().hashCode() : 0);
		return result;
	}


	@Override
	public String toString() {
		return getType() + ":" + getIdentifier();
	}
}
