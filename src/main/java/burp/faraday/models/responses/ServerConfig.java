/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.responses;

import com.google.gson.annotations.SerializedName;

public class ServerConfig {

    @SerializedName("sso_enabled")
    private Boolean sso;

    public ServerConfig() {
    }

    public ServerConfig(Boolean sso) {
        this.sso = sso;
    }

    public Boolean getSSO() {
        return sso;
    }

    public void setSSO(Boolean sso) {
        this.sso = sso;
    }

    @Override
    public String toString() {
        return "ServerConfig{" +
                "sso='" + sso + '\''+
                '}';
    }
}
