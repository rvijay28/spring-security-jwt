package org.hsvj.springjwt.filter;

import org.hsvj.springjwt.JwtUtility;
import org.hsvj.springjwt.exception.JwtTokenExpiredException;
import org.hsvj.springjwt.exception.JwtVerificationFailedException;
import org.hsvj.springjwt.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    private static final String AUTH_HEADER = "authorization";
    private static final String TOKEN_PREFIX = "Bearer ";

    @Autowired
    private JwtUtility jwtUtility;
    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = httpServletRequest.getHeader(AUTH_HEADER);
        String jwtToken = null;
        String username = null;
        try {
            if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
                jwtToken = authorizationHeader.substring(TOKEN_PREFIX.length()).trim();
                username = jwtUtility.getUsernameFromAccessToken(jwtToken);
            }

            if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

                if (jwtUtility.validateAccessToken(jwtToken, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }

            }
        }catch(JwtTokenExpiredException tokenExpiredException) {
            //refresh token here
            tokenExpiredException.printStackTrace();
        } catch (JwtVerificationFailedException jwtVerificationFailedException) {
            throw new ServletException("Token verification failed");
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
