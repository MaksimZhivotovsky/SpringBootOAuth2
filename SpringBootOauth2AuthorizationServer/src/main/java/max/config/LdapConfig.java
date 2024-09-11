package max.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
public class LdapConfig {

//    @Bean
//    public LdapContextSource ldapContextSource() {
//        LdapContextSource lcs = new LdapContextSource();
//        lcs.setUrl("ldap://localhost:10389");
//        lcs.setBase("dc=nishant,dc=com");
//        return lcs;
//    }

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://localhost:10389");
        contextSource.setBase("ou=system");
        contextSource.setUserDn("uid=admin,ou=system");
        contextSource.setPassword("12345");
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }
}
