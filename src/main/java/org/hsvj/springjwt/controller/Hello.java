package org.hsvj.springjwt.controller;

import org.hsvj.springjwt.JwtUtility;
import org.hsvj.springjwt.model.AuthenticationRequest;
import org.hsvj.springjwt.model.AuthenticationResponse;
import org.hsvj.springjwt.model.RefreshAuthenticationTokenRequest;
import org.hsvj.springjwt.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

@RestController
public class Hello {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtUtility jwtUtility;
    @RequestMapping("/hello")
    public String sayHello() {
        return "Hello, Sprint JWT!";
    }
    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> generateToken(@RequestBody AuthenticationRequest request) throws Exception{
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(), request.getPassword(), null));
        }catch( BadCredentialsException e) {
            throw new Exception("Invalid username or password", e);
        }
        final UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(request.getUsername());
        final String accessJwt = jwtUtility.generateJwtAccessToken(userDetails);
        final String refreshJwt = jwtUtility.generateJwtRefreshToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(accessJwt, refreshJwt));
    }
    @PostMapping(value = "/authenticate/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshAuthenticationTokenRequest request)
            throws HttpClientErrorException {
        try {
            String username = jwtUtility.validateRefreshToken(request.getrefreshtoken());
            final UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
            final String accessJwt = jwtUtility.generateJwtAccessToken(userDetails);
            final String refreshJwt = jwtUtility.generateJwtRefreshToken(userDetails);
            return ResponseEntity.ok(new AuthenticationResponse(accessJwt, refreshJwt));

        }catch(Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
