package org.hsvj.springjwt.exception;

public class JwtTokenExpiredException extends Exception{

    public JwtTokenExpiredException() {
    }

    public JwtTokenExpiredException(String message) {
        super(message);
    }

    public JwtTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtTokenExpiredException(Throwable cause) {
        super(cause);
    }

    public JwtTokenExpiredException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
