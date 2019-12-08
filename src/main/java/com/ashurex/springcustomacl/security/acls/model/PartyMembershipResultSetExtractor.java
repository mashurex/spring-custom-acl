package com.ashurex.springcustomacl.security.acls.model;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import com.ashurex.springcustomacl.security.acls.domain.MembershipPartyType;
import com.ashurex.springcustomacl.security.acls.domain.PartyMembership;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.Permission;

/**
 * @author Mustafa Ashurex
 */
public class PartyMembershipResultSetExtractor implements ResultSetExtractor<List<PartyMembership>> {
	private final PermissionFactory permissionFactory;

	public PartyMembershipResultSetExtractor(PermissionFactory permissionFactory) {
		this.permissionFactory = permissionFactory;
	}

	@Override
	public List<PartyMembership> extractData(ResultSet rs) throws SQLException, DataAccessException {
		LinkedList<PartyMembership> partyMemberships = new LinkedList<>();
		while (rs.next()) {
			Long id = rs.getLong("id");
			MembershipPartyType partyType = MembershipPartyType.valueOf(rs.getString("party_type"));
			String username = rs.getString("username");
			Long userId = rs.getLong("user_id");
			Long partyId = rs.getLong("party_id");
			String partyCode = rs.getString("party_code");
			String parentIdentity = rs.getString("parent_identity");
			String parentPartyType = rs.getString("parent_party_type");
			boolean isInheriting = rs.getBoolean("inheriting");
			int mask = rs.getInt("permission_mask");
			Permission permission = permissionFactory.buildFromMask(mask);

			PartyMembership p = new PartyMembership(permission);
			p.setId(id);
			p.setPartyType(partyType);
			p.setPartyId(partyId);
			p.setPartyCode(partyCode);
			p.setUserId(userId);
			p.setUsername(username);
			p.setInheriting(isInheriting);
			if (null != parentIdentity && null != parentPartyType) {
				PartyObjectIdentity pid = new PartyObjectIdentity(MembershipPartyType.valueOf(parentPartyType),
																  parentIdentity);
				p.setParentIdentity(pid);
			}

			partyMemberships.add(p);
		}
		return partyMemberships;
	}
}
