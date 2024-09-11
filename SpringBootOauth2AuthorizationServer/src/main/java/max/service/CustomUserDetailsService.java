package max.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import max.entity.LdapUser;
import max.entity.User;
import max.repository.LdapUserRepository;
import max.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final LdapUserRepository ldapUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${isLDAP}")
    private Boolean isLDAP;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("loadUserByUsername email {}", email);
        if (Boolean.TRUE.equals(isLDAP)) {
            LdapUser ldapUser = ldapUserRepository.findByEmail(email);
            if(ldapUser == null) {
                throw  new UsernameNotFoundException("No User Found");
            }

            String pass = ldapUser.getPassword();
            String passEnecod = passwordEncoder.encode(ldapUser.getPassword());

            return new org.springframework.security.core.userdetails.User(
                    ldapUser.getEmail(),
//                    ldapUser.getDescription(),
//                    passwordEncoder.encode(ldapUser.getPassword()),
                    ldapUser.getPassword(),
                    true,
                    true,
                    true,
                    true,
                    getAuthorities(List.of( "USER"))
            );


        } else {
            User user = userRepository.findByEmail(email);
            if(user == null) {
                throw  new UsernameNotFoundException("No User Found");
            }
            return new org.springframework.security.core.userdetails.User(
                    user.getEmail(),
                    user.getPassword(),
                    user.isEnabled(),
                    true,
                    true,
                    true,
                    getAuthorities(List.of((user.getRole().trim().isEmpty()) ? "Admin" : user.getRole()))
            );
        }



    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<String> roles) {
        List<GrantedAuthority>  authorities = new ArrayList<>();
        for(String role: roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }
}
