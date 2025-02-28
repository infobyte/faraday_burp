/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday;

import burp.faraday.exceptions.http.ConflictException;
import burp.faraday.exceptions.http.UnauthorizedException;
import burp.faraday.exceptions.http.BadRequestException;
import burp.faraday.models.Workspace;
import burp.faraday.models.WorkspaceWrapper;
import burp.faraday.models.requests.SecondFactor;
import burp.faraday.models.requests.User;
import burp.faraday.models.responses.CreatedObjectEntity;
import burp.faraday.models.responses.LoginStatus;
import burp.faraday.models.responses.ServerConfig;
import burp.faraday.models.responses.ServerInfo;
import burp.faraday.models.vulnerability.Host;
import burp.faraday.models.vulnerability.Service;
import burp.faraday.models.vulnerability.Vulnerability;
import burp.faraday.models.vulnerability.Command;
import feign.Headers;
import feign.Param;
import feign.RequestLine;

import java.util.List;


public interface FaradayServerAPI {

    /**
     * Fetches the info of the current Faraday Server
     *
     * @return An instance of {@link ServerInfo} describing the Faraday Server
     */
    @RequestLine("GET /_api/v3/info")
    @Headers("Content-Type: application/json")
    ServerInfo getInfo();

    /**
     * Fetches the config of the current Faraday Server
     *
     * @return An instance of {@link ServerConfig} describing the Faraday Server
     */
    @RequestLine("GET /_api/config")
    @Headers("Content-Type: application/json")
    ServerConfig getConfig();

    /**
     * Attempts to login using the provided {@link User} credentials.
     *
     * @param user The user to login.
     *
     * @return An instance of {@link LoginStatus} describing the response of the server.
     *
     * @throws UnauthorizedException or BadRequestException If we were unable to authenticate the user.
     */
    @RequestLine("POST /_api/login")
    @Headers("Content-Type: application/json")
    LoginStatus login(User user) throws UnauthorizedException, BadRequestException;

    /**
     * Attempts to verify the token provided in {@link SecondFactor} against the Server,
     *
     * @param secondFactor The object containing the second factor token.
     *
     * @return An instance of {@link LoginStatus} describing the response of the server.
     *
     * @throws UnauthorizedException If we were unable to authenticate the token.
     */
    @RequestLine("POST /_api/confirmation")
    @Headers("Content-Type: application/json")
    LoginStatus verifyToken(SecondFactor secondFactor) throws UnauthorizedException;

    /**
     * Fetches the session from the Server. This is used to maintain the cookie up to date.
     *
     * @throws UnauthorizedException If the session has already expired.
     */
    @RequestLine("GET /_api/session")
    @Headers("Content-Type: application/json")
    void getSession() throws UnauthorizedException;

    /**
     * Lists the workspaces available to the user.
     *
     * @return a list of {@link Workspace} instances.
     *
     * @throws UnauthorizedException If the session has expired.
     */
    @RequestLine("GET /_api/v3/ws")
    @Headers("Content-Type: application/json")
//    List<Workspace> getWorkspaces() throws UnauthorizedException;
    WorkspaceWrapper getWorkspaces() throws UnauthorizedException;

    /**
     * Create a workspace.
     *
     * @return A Workspace Object
     *
     * @throws UnauthorizedException If the session has expired.
     */
    @RequestLine("POST /_api/v3/ws")
    @Headers("Content-Type: application/json")
    Workspace createWorkspace(Workspace workspace) throws UnauthorizedException, ConflictException;

    /**
     * Creates a command in the specified workspace.
     *
     * @param workspace The workspace in which the Host should be created.
     * @param command The command to create
     *
     * @return A {@link CreatedObjectEntity} describing the newly created object.
     *
     * @throws UnauthorizedException If the session has expired.
     * @throws ConflictException     If there was a conflict when creating the object.
     */
    @RequestLine("POST /_api/v3/ws/{workspace}/commands")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createCommand(@Param("workspace") String workspace, Command command) throws UnauthorizedException, ConflictException;

    /**
     * Creates a host in the specified workspace.
     *
     * @param workspace The workspace in which the Host should be created.
     * @param host      The host to create
     *
     * @return A {@link CreatedObjectEntity} describing the newly created object.
     *
     * @throws UnauthorizedException If the session has expired.
     * @throws ConflictException     If there was a conflict when creating the object.
     */
    @RequestLine("POST /_api/v3/ws/{workspace}/hosts")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createHost(@Param("workspace") String workspace, Host host) throws UnauthorizedException, ConflictException;

    /**
     * Creates a service in the specified workspace.
     *
     * @param workspace The workspace in which the Service should be created.
     * @param service   The service to create
     *
     * @return A {@link CreatedObjectEntity} describing the newly created object.
     *
     * @throws UnauthorizedException If the session has expired.
     * @throws ConflictException     If there was a conflict when creating the object.
     */
    @RequestLine("POST /_api/v3/ws/{workspace}/services")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createService(@Param("workspace") String workspace, Service service) throws BadRequestException, UnauthorizedException, ConflictException;

    /**
     * Creates a vulnerability in the specified workspace.
     *
     * @param workspace     The workspace in which the Vulnerability should be created.
     * @param vulnerability The vulnerability to create
     *
     * @return A {@link CreatedObjectEntity} describing the newly created object.
     *
     * @throws UnauthorizedException If the session has expired.
     */
    @RequestLine("POST /_api/v3/ws/{workspace}/vulns")
    @Headers("Content-Type: application/json")
    CreatedObjectEntity createVulnerability(@Param("workspace") String workspace, Vulnerability vulnerability) throws UnauthorizedException, ConflictException;
}
