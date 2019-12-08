package com.ashurex.springcustomacl.security.acls.domain;


import java.beans.Transient;
import java.io.Serializable;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentity;
import lombok.Data;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Permission;

/**
 * @author Mustafa Ashurex
 */
@Data
public class PartyMembership implements Permission, Serializable {
	private static final long serialVersionUID = 1L;
	private final Permission permission;
	private Long id;
	private MembershipPartyType partyType;
	private Long userId;
	private String username;
	private Long partyId;
	private String partyCode;
	private boolean inheriting;
	private PartyObjectIdentity parentIdentity;

	public PartyMembership(final Permission permission) {
		this.permission = permission;
	}

	@Override
	public int getMask() {
		return permission.getMask();
	}

	@Override
	public String getPattern() {
		return permission.getPattern();
	}

	@Transient
	public PrincipalSid getPrincipalSid() {
		return new PrincipalSid(getUsername());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}

		if (!(o instanceof Permission)) {
			return false;
		}

		Permission that = (Permission) o;

		return getPermission().equals(that);
	}

	@Override
	public int hashCode() {
		return getPermission().hashCode();
	}

	@Override
	public final String toString() {
		return this.getClass().getSimpleName() + "[" + getPattern() + "=" + getMask() + "]";
	}
}
