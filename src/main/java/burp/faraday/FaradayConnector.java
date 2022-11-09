/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday;


import burp.faraday.exceptions.*;
import burp.faraday.exceptions.http.BadRequestException;
import burp.faraday.exceptions.http.ConflictException;
import burp.faraday.exceptions.http.UnauthorizedException;
import burp.faraday.models.Workspace;
import burp.faraday.models.requests.SecondFactor;
import burp.faraday.models.requests.User;
import burp.faraday.models.responses.CreatedObjectEntity;
import burp.faraday.models.responses.ExistingObjectEntity;
import burp.faraday.models.responses.LoginStatus;
import burp.faraday.models.responses.ServerInfo;
import burp.faraday.models.vulnerability.Service;
import burp.faraday.models.vulnerability.Host;
import burp.faraday.models.vulnerability.Vulnerability;
import burp.faraday.models.vulnerability.Command;
import com.github.zafarkhaja.semver.Version;
import feign.*;
import feign.Client;
import feign.codec.Decoder;
import feign.codec.ErrorDecoder;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


import burp.faraday.http.FeignClientConfiguration;
import java.net.URL;
import java.net.MalformedURLException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

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
    private FaradayServerAPI faradayServerAPI;

    private String baseUrl = null;
    private boolean urlIsValid = false;

    private Workspace currentWorkspace = null;

    private static final CookieManager COOKIE_MANAGER = new CookieManager();

    public FaradayConnector(PrintWriter stdout) {
        this.stdout = stdout;
    }

    /**
     * Sets the base URL of the Faraday Server we are going to connect.
     *
     * @param baseUrl Base URL of the Faraday Server.
     */
    public void setBaseUrl(final String baseUrl, boolean ignoreSSLErrors) {
        Client client;
        Decoder decoder = new GsonDecoder();
        if (ignoreSSLErrors == true)
        {
          try{
                String host = new URL(baseUrl).getHost();
                client = FeignClientConfiguration.client(host);
                // Build an instance of Feign to communicate with the REST API
                faradayServerAPI = Feign.builder()
                        .logLevel(Logger.Level.FULL)
                        .client(client)

                        // Add the available cookies to every request
                        .requestInterceptor(this::addCookies)
                        .encoder(new GsonEncoder())

                        // Add a custom error decoder to dispatch the correct exceptions.
                        .errorDecoder(new FaradayErrorDecoder(decoder))

                        // Intercept requests and call this method to simulate a browser session.
                        .mapAndDecode((response, type) -> {
                            handleCookies(response.headers());
                            return response;
                        }, decoder)
                        .target(FaradayServerAPI.class, baseUrl);

            } catch (NoSuchAlgorithmException e){

            }
            catch (MalformedURLException e)
            {

            }catch (KeyManagementException e){

            }
        } else {
            faradayServerAPI = Feign.builder()
                    .logLevel(Logger.Level.FULL)
                    // Add the available cookies to every request
                    .requestInterceptor(this::addCookies)
                    .encoder(new GsonEncoder())

                    // Add a custom error decoder to dispatch the correct exceptions.
                    .errorDecoder(new FaradayErrorDecoder(decoder))

                    // Intercept requests and call this method to simulate a browser session.
                    .mapAndDecode((response, type) -> {
                        handleCookies(response.headers());
                        return response;
                    }, decoder)
                    .target(FaradayServerAPI.class, baseUrl);
        }

        this.baseUrl = baseUrl;
        this.urlIsValid = false;
    }

    /**
     * Add a header to the request template with the value of the stored cookies.
     */
    private void addCookies(RequestTemplate template) {
        URI uri = URI.create(this.baseUrl);
        COOKIE_MANAGER.getCookieStore().get(uri).stream()
                .map(HttpCookie::toString)
                .forEach(cookie -> template.header("Cookie", cookie));
    }

    /**
     * Sore the cookies that the server returned so that we can add them to future requests.
     */
    private void handleCookies(Map<String, Collection<String>> headers) {
        // From Map<String, Collection<String>> to Map<String, List<String>>
        Map<String, List<String>> h = headers.entrySet().stream()
                .collect(
                        Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> new ArrayList<>(entry.getValue()))
                );
        try {
            URI uri = URI.create(this.baseUrl);
            COOKIE_MANAGER.put(uri, h);
//            String sessionCookie = COOKIE_MANAGER.getCookieStore().get(uri).stream() // Stream<HttpCookie>
//                    .filter(cookie -> cookie.getName().equals("session"))
//                    .findFirst() // Optional<HttpCookie>
//                    .map(HttpCookie::getValue)
//                    .orElse("");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Parses a Faraday Server version and appends the '.0' if it is missing so that it can be parsed correctly.
     * This is done to ensure compatibility with the Version parsing library.
     *
     * @param version The raw version of the faraday server
     *
     * @return The parsed version of the Faraday Server
     */
    private Version parseVersion(String version) {
        if (version.split("\\.").length == 2) {
            version = version + ".0";
        }

        return Version.valueOf(version);
    }

    /**
     * Validates that the current baseUrl points to a valid Faraday Server.
     *
     * @throws InvalidFaradayServerException When the URL does not point to a valid Faraday Server.
     * @throws ServerTooOldException         When the server is running a version lower than 3.4.0
     */
    public void validateFaradayURL() throws ServerTooOldException, InvalidFaradayServerException {
        ServerInfo serverInfo;
        try {
            serverInfo = faradayServerAPI.getInfo();
        } catch (FeignException e) {
            throw new InvalidFaradayServerException();
        }

        final Version serverVersion;

        if (serverInfo.getVersion().contains("-")) {
            // The version has the license type, we should strip it.
            final String[] versionParts = serverInfo.getVersion().split("-");

            serverVersion = parseVersion(versionParts[1]);
        } else {
            // The server is the White edition, no license type in the version.
            serverVersion = parseVersion(serverInfo.getVersion());
        }

        log("Faraday Server version: " + serverVersion.toString());

        if (serverVersion.lessThan(MINIMUM_VERSION)) {
            log("Faraday server is too old to be used with this extension. Please upgrade to the latest version.");
            throw new ServerTooOldException();
        }

        this.urlIsValid = true;
        log("Faraday server found!");
    }

    /**
     * Issues a log in request to the Faraday Server, and stores the cookie if successful.
     *
     * @param username The username of the account
     * @param password The password of the account
     *
     * @throws InvalidFaradayServerException If the Faraday Server URL is not valid, or an error occurred while sending the request.
     * @throws InvalidCredentialsException   If the credentials were invalid.
     * @throws SecondFactorRequiredException If we need a 2FA token to login.
     */
    public void login(final String username, final String password)
            throws InvalidFaradayServerException,
            InvalidCredentialsException,
            SecondFactorRequiredException {

        if (!this.urlIsValid) {
            throw new InvalidFaradayServerException();
        }

        // Lets clear the cookies just in case.
        FaradayConnector.clearCookies();

        final User user = new User(username, password);

        LoginStatus loginStatus;
        try {
            loginStatus = faradayServerAPI.login(user);
        } catch (BadRequestException e) {
            log("Invalid credentials.");
            throw new InvalidCredentialsException();
        } catch (UnauthorizedException e) {
            log("Invalid credentials.");
            throw new InvalidCredentialsException();
        }

        if (loginStatus.getCode() == 202) {
            log("2FA token is required.");
            throw new SecondFactorRequiredException();
        }

        assert loginStatus.getCode() == 200;

        try {
            this.getSession();
        } catch (CookieExpiredException ignored) {
        }
    }


    /**
     * Issues a request to verify the 2FA token. If the verification is successful, the stored session cookie is updated.
     *
     * @param token The token to verify.
     *
     * @throws InvalidFaradayServerException If the Faraday Server URL is not valid, or an error occurred while sending the request.
     * @throws InvalidCredentialsException   If the token could not be verified.
     */
    void verify2FAToken(final String token) throws InvalidFaradayServerException, InvalidCredentialsException {

        if (!this.urlIsValid) {
            throw new InvalidFaradayServerException();
        }

        LoginStatus loginStatus;
        try {
            loginStatus = faradayServerAPI.verifyToken(new SecondFactor(token));
        } catch (UnauthorizedException e) {
            log("Invalid credentials.");
            throw new InvalidCredentialsException();
        }

        assert loginStatus.getCode() == 200;

        try {
            this.getSession();
        } catch (CookieExpiredException ignored) {
        }
    }

    /**
     * Issues a request to fetch the latest session data from the server. Should be used to renew the cookie.
     *
     * @throws CookieExpiredException If the cookie has already expired
     */
    private void getSession() throws CookieExpiredException {

        log("Fetching session info");

        try {
            faradayServerAPI.getSession();
        } catch (UnauthorizedException e) {
            log("The cookie has expired.");
            throw new CookieExpiredException();
        }

        log("Session set.");
    }

    /**
     * Fetches a list of workspaces from the server.
     *
     * @return A list of workspaces this user has access to.
     *
     * @throws InvalidFaradayServerException If the Faraday Server URL is not valid, or an error occurred while sending the request.
     */
    List<Workspace> getWorkspaces() throws InvalidFaradayServerException, CookieExpiredException {
        if (!this.urlIsValid) {
            throw new InvalidFaradayServerException();
        }

        log("Fetching workspaces");

        try {
            return faradayServerAPI.getWorkspaces();
        } catch (UnauthorizedException e) {
            throw new CookieExpiredException();
        }
    }

    /**
     *
     */
    public void logout() {
        log("Logging out");

        this.faradayServerAPI = null;
        this.urlIsValid = false;
    }


    private void log(final String msg) {
        this.stdout.println("[CONNECTOR] " + msg);
    }

    public Workspace getCurrentWorkspace() {
        return currentWorkspace;
    }

    void setCurrentWorkspace(Workspace currentWorkspace) {
        this.currentWorkspace = currentWorkspace;
    }

    /**
     * Create a new workspace.
     *
     * @param name The workspace to name.
     */
    public Workspace createWorkspace(final String name)
            throws InvalidFaradayServerException,
            ObjectNotCreatedException {
        if (!this.urlIsValid) {
            throw new InvalidFaradayServerException();
        }
        try {
            try {
                Workspace ws = new Workspace();
                ws.setName(name);
                ws.setActive(true);
                return faradayServerAPI.createWorkspace(ws);
            } catch (ConflictException e) {
                throw new ObjectNotCreatedException();
            }
        } catch (UnauthorizedException e) {
            throw new ObjectNotCreatedException();
        } catch (Exception e)
        {
            throw new ObjectNotCreatedException();
        }
    }

    /**
     * Adds a vulnerability to the current workspace.
     *
     * @param vulnerability The vulnerability to create.
     */
    public int addCommandToWorkspace(final Command command, final Workspace workspace)
            throws InvalidFaradayServerException,
            ObjectNotCreatedException {
        if (!this.urlIsValid) {
            throw new InvalidFaradayServerException();
        }
        try {

            // First create the host and store the id.
            try {
                return faradayServerAPI.createCommand(workspace.getName(), command).getId();
            } catch (ConflictException e) {
                throw new ObjectNotCreatedException();
            }
        } catch (UnauthorizedException e) {
            throw new ObjectNotCreatedException();
        } catch (Exception e)
        {
            throw new ObjectNotCreatedException();
        }
    }

    /**
     * Adds a vulnerability to the current workspace.
     *
     * @param vulnerability The vulnerability to create.
     */
    void addVulnerabilityToWorkspace(final Vulnerability vulnerability, final Workspace workspace)
            throws InvalidFaradayServerException,
            ObjectNotCreatedException {

        if (!this.urlIsValid) {
            throw new InvalidFaradayServerException();
        }

        try {

            // First create the host and store the id.
            CreatedObjectEntity hostEntity;
            try {
                Host host = vulnerability.getHost();
                host.setCommandId(vulnerability.getCommandId());
                hostEntity = faradayServerAPI.createHost(workspace.getName(), host);
            } catch (ConflictException e) {
                hostEntity = e.getExistingObject().getObject();
            }

            // Instantiate the Service and set the parent ID
            final Service service = vulnerability.getService();
            service.setParent(hostEntity.getId());
            service.setCommandId(vulnerability.getCommandId());
            CreatedObjectEntity serviceEntity;
            try {
                serviceEntity = faradayServerAPI.createService(workspace.getName(), service);
            } catch (ConflictException e) {
                serviceEntity = e.getExistingObject().getObject();
            }

            // Set the parent ID of the vulnerability, and issue the creation request.
            vulnerability.setParent(serviceEntity.getId());
            try {
                final CreatedObjectEntity vulnerabilityEntity = faradayServerAPI.createVulnerability(workspace.getName(), vulnerability);
            } catch (Exception e) {
                throw new ObjectNotCreatedException();
            }
            //log("Created vulnerability " + vulnerabilityEntity.getId());

        } catch (UnauthorizedException e) {
            throw new ObjectNotCreatedException();
        }
    }

    /**
     * Decodes errors returned by the server and returns the correct exception to be raised.
     */
    static class FaradayErrorDecoder implements ErrorDecoder {

        final Decoder decoder;
        final ErrorDecoder defaultDecoder = new ErrorDecoder.Default();

        FaradayErrorDecoder(Decoder decoder) {
            this.decoder = decoder;
        }

        @Override
        public Exception decode(String methodKey, Response response) {
            try {
                switch (response.status()) {
                    case 400:
                        return new BadRequestException();
                    case 401:
                        return new UnauthorizedException();
                    case 409:
                        ExistingObjectEntity existingObject = (ExistingObjectEntity) decoder.decode(response, ExistingObjectEntity.class);

                        return new ConflictException(existingObject);

                    default:
                        return FeignException.errorStatus(methodKey, response);
                }
            } catch (IOException fallbackToDefault) {
                return defaultDecoder.decode(methodKey, response);
            }
        }
    }

    /**
     * Clears the cookies from the cookie jar to start a fresh session.
     */
    static void clearCookies() {
        COOKIE_MANAGER.getCookieStore().removeAll();
    }

}

