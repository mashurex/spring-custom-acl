package com.ashurex.springcustomacl.security;

import java.util.List;
import com.ashurex.springcustomacl.security.acls.domain.MembershipPartyType;
import com.ashurex.springcustomacl.security.acls.domain.PartyMembership;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * @author Mustafa Ashurex
 */
@NoRepositoryBean
public interface PartyMembershipRepository extends CrudRepository<PartyMembership, Long> {
	List<PartyMembership> findAllForUsername(String username);

	List<PartyMembership> findAllOfPartyTypeForUsername(MembershipPartyType partyType, String username);

}
