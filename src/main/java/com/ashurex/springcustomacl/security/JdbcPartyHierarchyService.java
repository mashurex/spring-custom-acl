package com.ashurex.springcustomacl.security;

import java.util.Collections;
import java.util.List;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentityRetrievalStrategy;
import com.ashurex.springcustomacl.security.acls.model.PartyObjectIdentity;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.model.ObjectIdentity;

/**
 * JDBC implementation of {@link PartyHierarchyService}.
 *
 * @author Mustafa Ashurex
 */
public class JdbcPartyHierarchyService implements PartyHierarchyService, InitializingBean {
	private final PartyObjectIdentityRetrievalStrategy partyIdRetriever;

	public JdbcPartyHierarchyService(JdbcTemplate jdbcTemplate, PartyObjectIdentityRetrievalStrategy pids) {
		this.partyIdRetriever = pids;
		// ... JdbcTemplate used for queries removed from this example ...
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		// ... initialization code ...
	}

	@Override
	public PartyObjectIdentity getPartyIdentity(ObjectIdentity id) {
		if (null == id) {
			return null;
		}

		if (id instanceof PartyObjectIdentity) {
			return (PartyObjectIdentity) id;
		}

		return partyIdRetriever.createObjectIdentity(id.getIdentifier(), id.getType());
	}

	@Override
	public List<PartyObjectIdentity> getAncestors(ObjectIdentity oid) {
		// ... implementation of retrieving ancestors ...
		return Collections.emptyList();
	}


	@Override
	public List<PartyObjectIdentity> getPredecessors(ObjectIdentity oid) {
		// ... implementation of retrieving predecessors ...
		return Collections.emptyList();
	}
}
