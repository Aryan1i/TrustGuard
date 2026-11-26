package com.trustguard.security;

import com.trustguard.entity.UserEntity;
import com.trustguard.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        String springRole = user.getRole().startsWith("ROLE_") ? user.getRole() : "ROLE_" + user.getRole();
        return new User(
                user.getUsername(),
                user.getPasswordHash(),
                user.isActive(),
                true,
                true,
                true,
                List.of(new SimpleGrantedAuthority(springRole))
        );
    }
}
