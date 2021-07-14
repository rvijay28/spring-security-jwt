package org.hsvj.springjwt.exception;

public class JwtVerificationFailedException extends Exception {
    public JwtVerificationFailedException() {
    }

    public JwtVerificationFailedException(String message) {
        super(message);
    }

    public JwtVerificationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtVerificationFailedException(Throwable cause) {
        super(cause);
    }

    public JwtVerificationFailedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
