/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.responses;

import com.google.gson.annotations.SerializedName;

public class ServerInfo {

    @SerializedName("Faraday Server")
    private String status;

    @SerializedName("Version")
    private String version;

    public ServerInfo() {
    }

    public ServerInfo(String status, String version) {
        this.status = status;
        this.version = version;
    }

    public String getStatus() {
        return status;
    }

    public String getVersion() {
        return version;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public String toString() {
        return "ServerInfo{" +
                "status='" + status + '\'' +
                ", version='" + version + '\'' +
                '}';
    }
}
