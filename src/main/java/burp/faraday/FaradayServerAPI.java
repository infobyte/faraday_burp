/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday;

import burp.faraday.exceptions.http.ConflictException;
import burp.faraday.exceptions.http.UnauthorizedException;
import burp.faraday.models.requests.SecondFactor;
import burp.faraday.models.requests.User;
import burp.faraday.models.responses.CreatedObjectEntity;
import burp.faraday.models.responses.LoginStatus;
import burp.faraday.models.responses.ServerInfo;
import burp.faraday.models.responses.SessionInfo;
import burp.faraday.models.vulnerability.Host;
import burp.faraday.models.vulnerability.Service;
import burp.faraday.models.vulnerability.Vulnerability;
import feign.Headers;
import feign.Param;
import feign.RequestLine;

import java.util.List;


public interface FaradayServerAPI {

    @RequestLine("GET /_api/v2/info")
    @Headers("Content-Type: application/json")
    ServerInfo getInfo();

    @RequestLine("POST /_api/login")
    @Headers("Content-Type: application/json")
    LoginStatus login(User user) throws UnauthorizedException;

    @RequestLine("POST /_api/confirmation")
    @Headers("Content-Type: application/json")
    LoginStatus verifyToken(SecondFactor secondFactor) throws UnauthorizedException;

    @RequestLine("GET /_api/session")
    @Headers("Content-Type: application/json")
    SessionInfo getSession() throws UnauthorizedException;

    @RequestLine("GET /_api/v2/ws")
    @Headers("Content-Type: application/json")
    List<Workspace> getWorkspaces() throws UnauthorizedException;

    @RequestLine("POST /_api/v2/ws/{workspace}/hosts/")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createHost(@Param("workspace") String workspace, Host host) throws UnauthorizedException, ConflictException;

    @RequestLine("POST /_api/v2/ws/{workspace}/services/")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createService(@Param("workspace") String workspace, Service service) throws UnauthorizedException, ConflictException;

    @RequestLine("POST /_api/v2/ws/{workspace}/vulns/")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createVulnerability(@Param("workspace") String workspace, Vulnerability vulnerability) throws UnauthorizedException;
}
