package max.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
public class LdapConfig {

    @Value("${ldapUrl}")
    private String ldapUrl;
    @Value("${ldapBase}")
    private String ldapBase;

    @Bean
    public LdapContextSource ldapContextSource() {
        LdapContextSource lcs = new LdapContextSource();
        lcs.setUrl(ldapUrl);
        lcs.setBase(ldapBase);
        return lcs;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(ldapContextSource());
    }
}
