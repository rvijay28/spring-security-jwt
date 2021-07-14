package org.hsvj.springjwt.model;

public class RefreshAuthenticationTokenRequest {

    private String refreshtoken;

    public RefreshAuthenticationTokenRequest() {
    }

    public RefreshAuthenticationTokenRequest(String refreshtoken) {
        this.refreshtoken = refreshtoken;
    }

    public String getrefreshtoken() {
        return refreshtoken;
    }

    public void setrefreshtoken(String refreshtoken) {
        this.refreshtoken = refreshtoken;
    }
}
