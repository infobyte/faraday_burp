/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.responses;

import com.google.gson.annotations.SerializedName;

import java.util.Arrays;

public class SessionInfo {

    @SerializedName("csrf_token")
    private String csrfToken;

    private String email;
    private String name;
    private String role;
    private String username;

    private String[] roles;

    @SerializedName("state_opt")
    private int stateOTP;

    public SessionInfo() {

    }

    public SessionInfo(String csrfToken, String email, String name, String role, String username, String[] roles, int stateOTP) {
        this.csrfToken = csrfToken;
        this.email = email;
        this.name = name;
        this.role = role;
        this.username = username;
        this.roles = roles;
        this.stateOTP = stateOTP;
    }

    public String getCsrfToken() {
        return csrfToken;
    }

    public void setCsrfToken(String csrfToken) {
        this.csrfToken = csrfToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String[] getRoles() {
        return roles;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }

    public int getStateOTP() {
        return stateOTP;
    }

    public void setStateOTP(int stateOTP) {
        this.stateOTP = stateOTP;
    }

    @Override
    public String toString() {
        return "SessionInfo{" +
                "csrfToken='" + csrfToken + '\'' +
                ", email='" + email + '\'' +
                ", name='" + name + '\'' +
                ", role='" + role + '\'' +
                ", username='" + username + '\'' +
                ", roles=" + Arrays.toString(roles) +
                ", stateOTP=" + stateOTP +
                '}';
    }
}
