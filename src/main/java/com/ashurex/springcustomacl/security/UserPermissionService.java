package com.ashurex.springcustomacl.security;

/**
 * @author Mustafa Ashurex
 */
public interface UserPermissionService {
	boolean hasFirmMembership(String username, Long firmId);

	void refreshPermissions(String username);
}
