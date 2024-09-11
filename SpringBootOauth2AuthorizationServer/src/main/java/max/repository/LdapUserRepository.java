package max.repository;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;
import max.entity.LdapUser;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@Slf4j
@Service
@RequiredArgsConstructor
public class LdapUserRepository {

    private final LdapTemplate ldapTemplate;

    public LdapUser findByUid(String uid) {
        return ldapTemplate.findOne(query().where("uid").is(uid), LdapUser.class);
    }

    public LdapUser findByEmail(String email) {
        return ldapTemplate.findOne(query().where("mail").is(email), LdapUser.class);
    }
}
