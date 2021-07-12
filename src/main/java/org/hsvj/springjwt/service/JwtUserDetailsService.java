package org.hsvj.springjwt.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //{noop} is used along with plain text password for the default password encoder to work
        //NoOpPasswordEncoder is deprecated and should not be used
        return new User("admin", "{noop}admin123", new ArrayList<>());
    }
}
