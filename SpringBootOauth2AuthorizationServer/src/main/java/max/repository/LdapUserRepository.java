package max.repository;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import max.entity.LdapUser;

import java.util.Optional;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@Slf4j
@Repository
@RequiredArgsConstructor
public class LdapUserRepository {

    private final LdapTemplate ldapTemplate;

    public void authenticate(String mail, String password) {
        ldapTemplate.authenticate(query().where("mail").is(mail), password);
    }

    public LdapUser findByUid(String uid) {

        try {
            return ldapTemplate.findOne(query().where("uid").is(uid), LdapUser.class);
        } catch (Exception e) {
            log.error("LdapUserRepository findByUid e {}", e.getMessage());
            throw  new BadCredentialsException("Неверный email или пароль");
        }
    }

    public LdapUser findByEmail(String email) {
        try {
            return ldapTemplate.findOne(query().where("mail").is(email), LdapUser.class);
        } catch (Exception e) {
            log.error("LdapUserRepository findByEmail e {}", e.getMessage());
            throw  new BadCredentialsException("Неверный email или пароль");
        }
    }
}
