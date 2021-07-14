package org.hsvj.springjwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.hsvj.springjwt.exception.JwtTokenExpiredException;
import org.hsvj.springjwt.exception.JwtVerificationFailedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtility implements Serializable {

    private static final long serialVersionUID = -2550185165626007488L;

    public static final long JWT_ACCESS_TOKEN_VALIDITY = TimeUnit.SECONDS.toMillis(60);

    public static final long JWT_REFRESH_TOKEN_VALIDITY = TimeUnit.HOURS.toMillis(24L);

    public static final String TOKEN_PREFIX = "Bearer ";

    //secret key has to be 64 characters or more
    private static final String ACCESS_TOKEN_SECRET_KEY = "OQrKaqmVDPfI3dO0hpCMVhHdlkfEfWRDlXk3DpCsKnCjZIiu3HYtpub0TrLUWyzW";

    //secret key has to be 64 characters or more
    private static final String REFRESH_TOKEN_SECRET_KEY = "DIQqBmXeNB3sBN0c9C7bF3yiqgKkrJqJYyH6onaNKAv6uYCO8PkqFkLZOcFk1jr0";

    public String getUsernameFromAccessToken(String token)  throws
            JwtTokenExpiredException, JwtVerificationFailedException{
            return getJwtClaimsSetForToken(token, ACCESS_TOKEN_SECRET_KEY).getSubject();
    }
    public String getUsernameFromRefreshToken(String token)  throws
            JwtTokenExpiredException, JwtVerificationFailedException {
        return getJwtClaimsSetForToken(token, REFRESH_TOKEN_SECRET_KEY).getSubject();
    }

    public Date getExpirationDateFromAccessToken(String token) throws
            JwtTokenExpiredException, JwtVerificationFailedException {
        return getJwtClaimsSetForToken(token, ACCESS_TOKEN_SECRET_KEY).getExpirationTime();
    }

    public String generateJwtAccessToken(UserDetails userDetails)  {
        String token = null;
        try {
            //Create HMAC signer
            JWSSigner signer = new MACSigner(ACCESS_TOKEN_SECRET_KEY);
            //Prepare JWT with claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .subject(userDetails.getUsername())
                        .issueTime(new Date())
                        .issuer("hsvj")
                        .audience(userDetails.getUsername())
                        .expirationTime(new Date(System.currentTimeMillis() + JWT_ACCESS_TOKEN_VALIDITY))
                        .build();

            //Signed JWT
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(
                    JWSAlgorithm.HS512), claimsSet);
            //Apply signature
            signedJWT.sign(signer);
            //return token
            token = signedJWT.serialize();
        }catch(Exception e) {
            e.printStackTrace();
            //throw new Exception("JWT token generation failed ", e.getCause());
        }
        return token;
    }
    public String generateJwtRefreshToken(UserDetails userDetails)  {
        String token = null;
        try {
            //Create HMAC signer
            JWSSigner signer = new MACSigner(REFRESH_TOKEN_SECRET_KEY);
            //Prepare JWT with claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(new Date())
                    .issuer("hsvj")
                    .audience(userDetails.getUsername())
                    .expirationTime(new Date(System.currentTimeMillis() + JWT_REFRESH_TOKEN_VALIDITY))
                    .build();

            //Signed JWT
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(
                    JWSAlgorithm.HS512), claimsSet);
            //Apply signature
            signedJWT.sign(signer);
            //return token
            token = signedJWT.serialize();
        }catch(Exception e) {
            e.printStackTrace();
            //throw new Exception("JWT token generation failed ", e.getCause());
        }
        return token;
    }

    public Boolean validateAccessToken(String token, UserDetails userDetails) throws
            JwtTokenExpiredException, JwtVerificationFailedException {
        final String username = userDetails.getUsername();
        return (username.equals(getUsernameFromAccessToken(token)) && !isAccessTokenExpired(token));
    }

    public String validateRefreshToken(String token) throws
            JwtTokenExpiredException, JwtVerificationFailedException {
        if (isRefreshTokenExpired(token)) {
            return null;
        }
        final String username = getUsernameFromRefreshToken(token);
        if (username == null || username.trim().equals("")) {
            throw new JwtVerificationFailedException("Invalid token");
        }
        return username;
    }

    private JWTClaimsSet getJwtClaimsSetForToken(String token, String secret) throws
            JwtTokenExpiredException, JwtVerificationFailedException  {
        JWTClaimsSet claimsSet = null;
        try{

            JWSVerifier jwsVerifier = new MACVerifier(secret);
            SignedJWT signedJWT = SignedJWT.parse(token);
            if (signedJWT.getJWTClaimsSet().getExpirationTime().before(new Date())) {
                throw new JwtTokenExpiredException("Token has expired");
            }
            if (!signedJWT.verify(jwsVerifier)) {
                throw new JwtVerificationFailedException("Token verification failed");
            };

            claimsSet = signedJWT.getJWTClaimsSet();
        }catch (JOSEException | ParseException e) {
            e.printStackTrace();
            /* throw new Exception("Unable to retrieve claim set from token ("
            + token + ")", e.getCause());*/
        }
        return claimsSet;
    }

    private boolean isAccessTokenExpired(String token) throws
            JwtTokenExpiredException, JwtVerificationFailedException {
        final Date expiration = getJwtClaimsSetForToken(token, ACCESS_TOKEN_SECRET_KEY).getExpirationTime();
        return expiration.before(new Date());
    }

    private boolean isRefreshTokenExpired(String token) throws
            JwtTokenExpiredException, JwtVerificationFailedException {
        final Date expiration = getJwtClaimsSetForToken(token, REFRESH_TOKEN_SECRET_KEY).getExpirationTime();
        return expiration.before(new Date());
    }
}
