package com.company.demo.security;

import com.company.demo.entity.User;
import io.jmix.core.Metadata;
import io.jmix.core.entity.EntityValues;
import io.jmix.core.security.UserRepository;
import io.jmix.security.role.RoleGrantedAuthorityUtils;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Primary
@Component("UserRepository")
public class DemoUserRepository implements UserRepository {

    private final Metadata metadata;
    private User systemUser;
    private User anonymousUser;
    private User adminUser;

    @Autowired
    protected RoleGrantedAuthorityUtils roleGrantedAuthorityUtils;

    public DemoUserRepository(Metadata metadata) {
        this.metadata = metadata;
    }

    @PostConstruct
    private void init() {
        systemUser = createSystemUser();
        anonymousUser = createAnonymousUser();
        adminUser = createAdminUser();
    }

    protected User createSystemUser() {
        User systemUser = metadata.create(User.class);
        EntityValues.setValue(systemUser, "username", "system");
        initSystemUser(systemUser);
        return systemUser;
    }

    protected User createAnonymousUser() {
        User anonymousUser = metadata.create(User.class);
        EntityValues.setValue(anonymousUser, "username", "anonymous");
        initAnonymousUser(anonymousUser);
        return anonymousUser;
    }

    protected void initSystemUser(final User systemUser) {
        final Collection<GrantedAuthority> authorities = getGrantedAuthoritiesBuilder()
                .addResourceRole(FullAccessRole.CODE)
                .build();
        systemUser.setAuthorities(authorities);
    }

    protected User createAdminUser() {
        User user = metadata.create(User.class);
        user.setUsername("admin");
        user.setPassword("{noop}admin");
        final Collection<GrantedAuthority> authorities = getGrantedAuthoritiesBuilder()
                .addResourceRole(FullAccessRole.CODE)
                .build();
        user.setAuthorities(authorities);
        return user;
    }

    protected void initAnonymousUser(final User anonymousUser) {
    }

    @Override
    public UserDetails getSystemUser() {
        return systemUser;
    }

    @Override
    public UserDetails getAnonymousUser() {
        return anonymousUser;
    }

    @Override
    public List<? extends UserDetails> getByUsernameLike(String substring) {
        return List.of(adminUser);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return adminUser;
    }

    protected GrantedAuthoritiesBuilder getGrantedAuthoritiesBuilder() {
        return new GrantedAuthoritiesBuilder();
    }

    public class GrantedAuthoritiesBuilder {

        private List<GrantedAuthority> authorities = new ArrayList<>();

        /**
         * Adds a resource role by its code.
         */
        public GrantedAuthoritiesBuilder addResourceRole(String code) {
            GrantedAuthority authority = roleGrantedAuthorityUtils.createResourceRoleGrantedAuthority(code);
            authorities.add(authority);
            return this;
        }

        /**
         * Adds a row-level role by its code.
         */
        public GrantedAuthoritiesBuilder addRowLevelRole(String code) {
            GrantedAuthority authority = roleGrantedAuthorityUtils.createRowLevelRoleGrantedAuthority(code);
            authorities.add(authority);
            return this;
        }

        /**
         * Builds a collection of authorities.
         */
        public Collection<GrantedAuthority> build() {
            return authorities;
        }
    }
}