package org.hsvj.springjwt.model;

public class AuthenticationResponse {

    private String accessJwt;
    private String refreshJwt;

    public AuthenticationResponse() {
    }

    public AuthenticationResponse(String accessJwt, String refreshJwt) {
        this.accessJwt = accessJwt;
        this.refreshJwt = refreshJwt;
    }

    public String getAccessJwt() {
        return accessJwt;
    }

    public void setAccessJwt(String accessJwt) {
        this.accessJwt = accessJwt;
    }

    public String getRefreshJwt() {
        return refreshJwt;
    }

    public void setRefreshJwt(String refreshJwt) {
        this.refreshJwt = refreshJwt;
    }
}
