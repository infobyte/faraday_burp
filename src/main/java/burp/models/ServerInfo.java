package burp.models;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ServerInfo {

    @JsonProperty("Faraday Server")
    private String status;

    @JsonProperty("Version")
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
