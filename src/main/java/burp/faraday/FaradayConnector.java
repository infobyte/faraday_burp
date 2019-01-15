/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday;


import burp.faraday.exceptions.*;
import burp.faraday.models.*;
import burp.faraday.models.requests.SecondFactor;
import burp.faraday.models.requests.User;
import burp.faraday.models.responses.CreatedObjectEntity;
import burp.faraday.models.responses.ExistingObjectEntity;
import burp.faraday.models.responses.ServerInfo;
import burp.faraday.models.responses.SessionInfo;
import burp.faraday.models.vulnerability.Host;
import burp.faraday.models.vulnerability.Service;
import burp.faraday.models.vulnerability.Vulnerability;
import com.github.zafarkhaja.semver.Version;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * This class provides the utilities necessary to connect to a Faraday Server and issue
 * authenticated requests to it.
 */
public class FaradayConnector {

    /**
     * Minimum version required to use the extension.
     */
    private static final Version MINIMUM_VERSION = Version.valueOf("3.4.0");

    private final PrintWriter stdout;
    private WebTarget baseUrl;

    private boolean urlIsValid = false;

    private Client client;

    private String cookie = null;
    private SessionInfo sessionInfo = null;

    private Workspace currentWorkspace = null;
    private FaradayEdition faradayEdition;

    public FaradayConnector(PrintWriter stdout) {
        this.stdout = stdout;

        client = ClientBuilder.newClient()
                .register(JacksonJsonProvider.class);
    }

    /**
     * Sets the base URL of the Faraday Server we are going to connect.
     *
     * @param baseUrl Base URL of the Faraday Server.
     */
    public void setBaseUrl(final String baseUrl) {

        if (baseUrl == null) {
            this.baseUrl = null;
        } else {
            this.baseUrl = client.target(baseUrl);
        }

        this.urlIsValid = false;
    }

    /**
     * Buils a target using the
     *
     * @param method
     *
     * @return
     */
    private WebTarget buildTargetForMethod(final String method) throws InvalidFaradayException {
        if (this.baseUrl == null) {
            throw new InvalidFaradayException();
        }
        return this.baseUrl.path("_api").path(method);
    }

    /**
     * @return
     */
    private WebTarget buildTargetForCurrentWorkspace() throws InvalidFaradayException {
        if (this.baseUrl == null) {
            throw new InvalidFaradayException();
        }
        return this.baseUrl.path("_api").path("v2").path("ws").path(currentWorkspace.getName());
    }

    private Version parseVersion(String version) {
        if (version.split("\\.").length == 2) {
            version = version + ".0";
        }

        return Version.valueOf(version);
    }

    /**
     * Validates that the current baseUrl points to a valid Faraday Server.
     *
     * @throws InvalidFaradayException When the URL does not point to a valid Faraday Server.
     * @throws ServerTooOldException   When the server is running a version lower than 3.4.0
     */
    public void validateFaradayURL() throws InvalidFaradayException, ServerTooOldException {

        WebTarget infoEndpoint = buildTargetForMethod("v2/info");

        log("Testing for running Faraday server at: " + infoEndpoint.getUri());

        Response response;
        try {
            response = get("v2/info");
        } catch (FaradayConnectionException e) {
            throw new InvalidFaradayException();
        }

        ServerInfo serverInfo = response.readEntity(ServerInfo.class);

        log(serverInfo.toString());

        final Version serverVersion;

        if (serverInfo.getVersion().contains("-")) {

            final String[] versionParts = serverInfo.getVersion().split("-");

            serverVersion = parseVersion(versionParts[1]);
            this.faradayEdition = FaradayEdition.fromName(versionParts[0]);
        } else {
            serverVersion = parseVersion(serverInfo.getVersion());
            this.faradayEdition = FaradayEdition.WHITE;
        }

        log("Faraday Server version: " + serverVersion.toString());

        if (serverVersion.lessThan(MINIMUM_VERSION)) {
            log("Faraday server is too old to be used with this extension. Please upgrade to the latest version.");
            throw new ServerTooOldException();
        }

        this.urlIsValid = response.getStatus() == 200;

        if (this.urlIsValid) {
            log("Faraday server found!");
        }

    }

    /**
     * @param target
     * @param authenticated
     *
     * @return
     */
    private Invocation.Builder buildRequest(final WebTarget target, boolean authenticated) {
        Invocation.Builder request = target
                .request(MediaType.APPLICATION_JSON);

        if (authenticated) {
            if (this.cookie == null) {
                throw new IllegalStateException("Attempt to perform an authenticated request without a cookie.");
            }
            request = request.cookie("session", this.cookie);
        }

        return request;
    }

    /**
     * @param method
     * @param authenticated
     *
     * @return
     */
    private Invocation.Builder buildRequest(final String method, boolean authenticated) throws InvalidFaradayException {
        WebTarget target = buildTargetForMethod(method);
        return buildRequest(target, authenticated);
    }

    /**
     * @param username
     * @param password
     *
     * @throws BaseFaradayException
     */
    public void login(final String username, final String password) throws BaseFaradayException {

        if (!this.urlIsValid) {
            throw new InvalidFaradayException();
        }

        User user = new User(username, password);

        Response response;
        try {
            response = buildTargetForMethod("login")
                    .request(MediaType.APPLICATION_JSON)
                    .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        } catch (ProcessingException e) {
            throw new InvalidFaradayException();
        }

        switch (response.getStatus()) {
            case 401:
                log("Invalid credentials.");
                throw new InvalidCredentialsException();
            case 202:
                log("2FA token is required.");
                this.cookie = response.getCookies().get("session").getValue();
                throw new SecondFactorRequiredException();
            case 200:
                this.cookie = response.getCookies().get("session").getValue();
        }

    }

    public void verify2FAToken(final String token) throws BaseFaradayException {

        if (!this.urlIsValid) {
            throw new InvalidFaradayException();
        }

        WebTarget target = buildTargetForMethod("confirmation");

        SecondFactor secondFactor = new SecondFactor(token);

        Response response;
        try {
            response = buildRequest(target, true).post(Entity.entity(secondFactor, MediaType.APPLICATION_JSON));

        } catch (ProcessingException e) {
            throw new InvalidFaradayException();
        }

        switch (response.getStatus()) {
            case 401:
            case 403:
                log("Invalid credentials.");
                throw new InvalidCredentialsException();
            case 200:
                this.cookie = response.getCookies().get("session").getValue();
        }

    }

    /**
     * @param target
     * @param authenticated
     * @param entity
     *
     * @return
     *
     * @throws InvalidFaradayException
     * @throws ObjectNotCreatedException
     * @throws ObjectAlreadyExistsException
     */
    public Response post(final WebTarget target, final boolean authenticated, Object entity)
            throws InvalidFaradayException,
            ObjectNotCreatedException,
            ObjectAlreadyExistsException {

        log("POST " + target.getUri().toString());

        Response response;
        try {
            response = buildRequest(target, authenticated).post(Entity.entity(entity, MediaType.APPLICATION_JSON));
            log("CODE " + response.getStatus());

        } catch (ProcessingException e) {
            throw new InvalidFaradayException();
        }

        if (response.getStatus() == Response.Status.CREATED.getStatusCode()) {
            return response;
        }

        if (response.getStatus() == Response.Status.CONFLICT.getStatusCode()) {
            throw new ObjectAlreadyExistsException(response.readEntity(ExistingObjectEntity.class));
        }

        log("code:" + response.getStatus());
        log("body: " + response.readEntity(String.class));

        throw new ObjectNotCreatedException();
    }

    /**
     * @throws BaseFaradayException
     */
    public void getSession() throws BaseFaradayException {

        log("Fetching session info");

        Response response = get("session", true);

        if (response.getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()) {
            log("Cookie expired.");
            this.cookie = "";
            throw new CookieExpiredException();
        }


        this.sessionInfo = response.readEntity(SessionInfo.class);

        Map<String, NewCookie> cookies = response.getCookies();
        if (cookies.containsKey("session")) {
            this.cookie = cookies.get("session").getValue();
        }

        log("Session set.");
        log(this.sessionInfo.toString());

    }

    /**
     * @param method
     * @param authenticated
     *
     * @return
     *
     * @throws FaradayConnectionException
     */
    private Response get(final String method, final boolean authenticated) throws FaradayConnectionException {
        try {
            return buildRequest(method, authenticated).get();
        } catch (ProcessingException | InvalidFaradayException e) {
            log(e.getMessage());
//            e.printStackTrace(this.stdout);
            throw new FaradayConnectionException();
        }
    }

    /**
     * @return
     *
     * @throws BaseFaradayException
     */
    public List<Workspace> getWorkspaces() throws BaseFaradayException {
        if (!this.urlIsValid) {
            throw new InvalidFaradayException();
        }

        log("Fetching workspaces");

        Response response = get("v2/ws", true);

        Workspace[] workspaceList = response.readEntity(Workspace[].class);

        return Arrays.asList(workspaceList);
    }

    /**
     * @param method
     *
     * @return
     *
     * @throws FaradayConnectionException
     */
    private Response get(final String method) throws FaradayConnectionException {
        return get(method, false);
    }

    /**
     *
     */
    public void logout() {
        log("Logging out");

        this.cookie = null;
        this.sessionInfo = null;
        setBaseUrl(null);
    }


    private void log(final String msg) {
        this.stdout.println("[CONNECTOR] " + msg);
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public Workspace getCurrentWorkspace() {
        return currentWorkspace;
    }

    public void setCurrentWorkspace(Workspace currentWorkspace) {
        this.currentWorkspace = currentWorkspace;
    }

    /**
     * @param vulnerability
     */
    public void addVulnToWorkspace(Vulnerability vulnerability) throws InvalidFaradayException, ObjectNotCreatedException {

        final int hostId = createHost(vulnerability.getHost());

        final Service service = vulnerability.getService();
        service.setParent(hostId);

        final int serviceId = createService(service);
        vulnerability.setParent(serviceId);

        final int vulnId = createVulnerability(vulnerability);

        log("Created vulnerability " + vulnId);


    }

    /**
     * @param host
     *
     * @return
     *
     * @throws InvalidFaradayException
     * @throws ObjectNotCreatedException
     */
    private int createHost(final Host host) throws InvalidFaradayException, ObjectNotCreatedException {
        log("Creating host: " + host.toString());

        WebTarget target = this.buildTargetForCurrentWorkspace().path("hosts/");

        return createObject(target, host);
    }

    /**
     * @param service
     *
     * @return
     *
     * @throws InvalidFaradayException
     * @throws ObjectNotCreatedException
     */
    private int createService(final Service service) throws InvalidFaradayException, ObjectNotCreatedException {
        log("Creating service: " + service.toString());

        WebTarget target = this.buildTargetForCurrentWorkspace().path("services/");

        return createObject(target, service);
    }

    /**
     * @param vulnerability
     *
     * @return
     *
     * @throws InvalidFaradayException
     * @throws ObjectNotCreatedException
     */
    private int createVulnerability(final Vulnerability vulnerability) throws InvalidFaradayException, ObjectNotCreatedException {
        log("Creating vulnerability: " + vulnerability.toString());

        WebTarget target = this.buildTargetForCurrentWorkspace().path("vulns/");

        return createObject(target, vulnerability);
    }

    /**
     * @param target
     * @param object
     *
     * @return
     *
     * @throws InvalidFaradayException
     * @throws ObjectNotCreatedException
     */
    private int createObject(final WebTarget target, final Object object) throws InvalidFaradayException, ObjectNotCreatedException {
        Response response;
        try {
            response = post(target, true, object);
        } catch (ObjectAlreadyExistsException e) {
            final ExistingObjectEntity existingObject = e.getExistingObjectEntity();

            log("Object already exists: " + existingObject);
            return existingObject.getObject().getId();
        }

        final CreatedObjectEntity createdObjectEntity = response.readEntity(CreatedObjectEntity.class);

        log("Created object: " + createdObjectEntity.toString());

        return createdObjectEntity.getId();

    }

    public FaradayEdition getFaradayEdition() {
        return faradayEdition;
    }
}

