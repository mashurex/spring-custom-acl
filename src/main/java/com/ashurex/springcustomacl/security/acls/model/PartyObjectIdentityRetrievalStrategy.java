package com.ashurex.springcustomacl.security.acls.model;

import java.io.Serializable;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityGenerator;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;

/**
 * @author Mustafa Ashurex
 */
public class PartyObjectIdentityRetrievalStrategy implements ObjectIdentityRetrievalStrategy, ObjectIdentityGenerator {

	@Override
	public PartyObjectIdentity createObjectIdentity(Serializable serializable, String s) {
		// TODO: Implement the actual creation of the identity.
		return null;
	}

	@Override
	public ObjectIdentity getObjectIdentity(Object o) {
		// TODO: Implement the actual lookup of the identity.
		return null;
	}
}
