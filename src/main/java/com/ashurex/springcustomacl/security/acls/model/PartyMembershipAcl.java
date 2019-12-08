package com.ashurex.springcustomacl.security.acls.model;

import java.util.ArrayList;
import java.util.List;
import lombok.NonNull;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AuditableAcl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.UnloadedSidException;
import org.springframework.util.Assert;

/**
 * ACL implementation based on a user's relationship to a party.
 *
 * @author Mustafa Ashurex
 */
public class PartyMembershipAcl implements Acl, MutableAcl, AuditableAcl {
	private final List<AccessControlEntry> aces = new ArrayList<>();
	private transient AclAuthorizationStrategy aclAuthorizationStrategy;
	private transient PermissionGrantingStrategy permissionGrantingStrategy;
	private boolean inheriting = false;
	private PartyObjectIdentity objectIdentity;
	private String id;
	private List<Sid> loadedSids;
	private Acl parent = null;

	/**
	 * @param id                         The unique key of the ACL entry from persistence.
	 * @param objectIdentity             The primary key of the object the ACL is for.
	 * @param isInheriting               If {@literal true} then children of {@literal objectIdentity} will inheirt this ACL.
	 * @param aclAuthorizationStrategy
	 * @param permissionGrantingStrategy
	 * @param loadedSids
	 */
	public PartyMembershipAcl(final String id,
							  final PartyObjectIdentity objectIdentity,
							  boolean isInheriting,
							  AclAuthorizationStrategy aclAuthorizationStrategy,
							  PermissionGrantingStrategy permissionGrantingStrategy,
							  List<Sid> loadedSids) {
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
		this.permissionGrantingStrategy = permissionGrantingStrategy;
		this.objectIdentity = objectIdentity;
		this.id = id;
		this.loadedSids = loadedSids;
		this.inheriting = isInheriting;
	}

	/**
	 * @param id                         The unique key of the ACL entry from persistence.
	 * @param objectIdentity             The primary key of the object the ACL is for.
	 * @param isInheriting               If {@literal true} then children of {@literal objectIdentity} will inheirt this ACL.
	 * @param parent                     The parent ACL of this ACL entry.
	 * @param aclAuthorizationStrategy
	 * @param permissionGrantingStrategy
	 * @param loadedSids
	 */
	public PartyMembershipAcl(final String id,
							  final PartyObjectIdentity objectIdentity,
							  boolean isInheriting,
							  final Acl parent,
							  AclAuthorizationStrategy aclAuthorizationStrategy,
							  PermissionGrantingStrategy permissionGrantingStrategy,
							  List<Sid> loadedSids) {
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
		this.permissionGrantingStrategy = permissionGrantingStrategy;
		this.objectIdentity = objectIdentity;
		this.id = id;
		this.loadedSids = loadedSids;
		this.inheriting = isInheriting;
		this.parent = parent;
	}

	@Override
	public void updateAuditing(int aceIndex, boolean auditSuccess, boolean auditFailure) {
		aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_AUDITING);
		verifyAceIndexExists(aceIndex);
		AccessControlEntry e = aces.get(aceIndex);
		AccessControlEntryImpl newEntry = new AccessControlEntryImpl(e.getId(),
																	 this,
																	 e.getSid(),
																	 e.getPermission(),
																	 e.isGranting(),
																	 auditSuccess,
																	 auditFailure);
		aces.set(aceIndex, newEntry);
	}

	@Override
	public void deleteAce(int aceIndex) throws NotFoundException {
		aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		verifyAceIndexExists(aceIndex);

		synchronized (aces) {
			this.aces.remove(aceIndex);
		}
	}

	private void verifyAceIndexExists(int aceIndex) {
		if (aceIndex < 0) {
			throw new NotFoundException("aceIndex must be greater than or equal to zero");
		}
		if (aceIndex >= this.aces.size()) {
			throw new NotFoundException("aceIndex must refer to an index of the AccessControlEntry list. " +
										"List size is " +
										aces.size() +
										", index was " +
										aceIndex);
		}
	}


	@Override
	public String getId() {
		return id;
	}

	public void addAce(AccessControlEntry ace) {
		this.aces.add(ace);
	}

	@Override
	public void insertAce(int atIndexLocation, @NonNull Permission permission, @NonNull Sid sid, boolean granting)
			throws NotFoundException {
		aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		if (atIndexLocation < 0) {
			throw new NotFoundException("atIndexLocation must be greater than or equal to zero");
		}
		if (atIndexLocation > this.aces.size()) {
			throw new NotFoundException(
					"atIndexLocation must be less than or equal to the size of the AccessControlEntry collection");
		}

		AccessControlEntryImpl ace = new AccessControlEntryImpl(null, this, sid, permission, granting, false, false);

		synchronized (aces) {
			this.aces.add(atIndexLocation, ace);
		}
	}

	@Override
	public void setParent(Acl newParent) {
		// This is left as a reminder, if we enable this method we need the security check.
		aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		// throw new UnsupportedOperationException("Parent ACLs cannot be set");
		this.parent = newParent;
	}

	@Override
	public void updateAce(int aceIndex, Permission permission) throws NotFoundException {
		aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		verifyAceIndexExists(aceIndex);

		synchronized (aces) {
			AccessControlEntryImpl ace = (AccessControlEntryImpl) aces.get(aceIndex);
			AccessControlEntryImpl newAce = new AccessControlEntryImpl(ace.getId(),
																	   ace.getAcl(),
																	   ace.getSid(),
																	   permission,
																	   ace.isGranting(),
																	   ace.isAuditSuccess(),
																	   ace.isAuditFailure());
			aces.set(aceIndex, newAce);
		}
	}

	@Override
	public List<AccessControlEntry> getEntries() {
		return aces;
	}

	@Override
	public ObjectIdentity getObjectIdentity() {
		return objectIdentity;
	}

	/**
	 * Since parties are not 'owned', this is always null.
	 *
	 * @return {@literal null}
	 */
	@Override
	public Sid getOwner() {
		return null;
	}

	@Override
	public void setOwner(Sid newOwner) {
		// This is left as a reminder, if we enable this method we need the security check.
		// aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
		throw new UnsupportedOperationException("SID ownership cannot be set");
	}

	/**
	 * Since party ACLs aren't inherited, this is always null.
	 *
	 * @return {@literal null}
	 */
	@Override
	public Acl getParentAcl() {
		return parent;
	}

	/**
	 * Since party ACLs aren't inheritied, this is always false.
	 *
	 * @return {@literal false}
	 */
	@Override
	public boolean isEntriesInheriting() {
		return inheriting;
	}

	@Override
	public void setEntriesInheriting(boolean entriesInheriting) {
		// This is left as a reminder, if we enable this method we need the security check.
		aclAuthorizationStrategy.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		this.inheriting = entriesInheriting;
		// throw new UnsupportedOperationException("ACL entry inheritance cannot be set");
	}

	@Override
	public boolean isGranted(@NonNull List<Permission> permission, @NonNull List<Sid> sids, boolean administrativeMode)
			throws NotFoundException, UnloadedSidException {
		Assert.notEmpty(permission, "Permissions required");
		Assert.notEmpty(sids, "SIDs required");

		if (!this.isSidLoaded(sids)) {
			throw new UnloadedSidException("ACL was not loaded for one or more SID");
		}

		return permissionGrantingStrategy.isGranted(this, permission, sids, administrativeMode);
	}

	@Override
	public boolean isSidLoaded(List<Sid> sids) {
		// If loadedSides is null, this indicates all SIDs were loaded
		// Also return true if the caller didn't specify a SID to find
		if ((this.loadedSids == null) || (sids == null) || (sids.size() == 0)) {
			return true;
		}

		// This ACL applies to a SID subset only. Iterate to check it applies.
		for (Sid sid : sids) {
			boolean found = false;

			for (Sid loadedSid : loadedSids) {
				if (sid.equals(loadedSid)) {
					// this SID is OK
					found = true;

					break; // out of loadedSids for loop
				}
			}

			if (!found) {
				return false;
			}
		}

		return true;
	}
}
