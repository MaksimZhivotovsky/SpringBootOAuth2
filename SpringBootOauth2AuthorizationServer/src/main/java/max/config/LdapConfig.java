package max.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
public class LdapConfig {

    @Bean
    public LdapContextSource ldapContextSource() {
        LdapContextSource lcs = new LdapContextSource();
        lcs.setUrl("ldap://localhost:10389");
        lcs.setBase("dc=nishant,dc=com");
        return lcs;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(ldapContextSource());
    }
}
