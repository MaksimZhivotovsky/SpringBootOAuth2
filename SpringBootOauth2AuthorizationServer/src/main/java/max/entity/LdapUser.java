package max.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.ldap.odm.annotations.DnAttribute;
import org.springframework.ldap.odm.annotations.Entry;
import org.springframework.ldap.odm.annotations.Id;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.naming.Name;
import java.util.Collection;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entry(objectClasses = {"inetOrgPerson", "organizationalPerson", "top"})
public final class LdapUser implements UserDetails {

    @Id
    private Name dn;
    @Attribute(name = "cn")
    @DnAttribute(value = "cn")
    private String fullName;
    @Attribute(name = "sn")
    private String lastName;
    @Attribute(name = "givenname")
    private String givenName;
    @Attribute(name = "mail")
    private String email;
    @Attribute(name = "description")
    private String description;
    @Attribute(name = "uid")
    private String uid;
    @Attribute(name = "userPassword")
    private String password;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getUsername() {
        return "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
