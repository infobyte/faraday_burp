package burp.faraday;


import burp.faraday.models.ServerInfo;
import burp.faraday.models.SessionInfo;
import burp.faraday.models.User;
import burp.faraday.exceptions.*;
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

public class FaradayConnector {

    private final PrintWriter stdout;
    private WebTarget baseUrl;

    private boolean urlIsValid = false;

    private Client client;

    private String cookie = null;
    private SessionInfo sessionInfo = null;

    public FaradayConnector(PrintWriter stdout) {
        this.stdout = stdout;

        client = ClientBuilder.newClient()
                .register(JacksonJsonProvider.class);
    }

    public void setBaseUrl(final String baseUrl) {

        if (baseUrl == null) {
            this.baseUrl = null;
        } else {
            this.baseUrl = client.target(baseUrl);
        }

        this.urlIsValid = false;
    }

    private WebTarget buildTargetForMethod(final String method) {
        return this.baseUrl.path("_api").path(method);
    }

    public void validateFaradayURL() throws InvalidFaradayException {

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

        this.urlIsValid = response.getStatus() == 200;

        if (this.urlIsValid) {
            log("Faraday server found!");
        }

    }

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
                throw new SecondFactorRequiredException();
            case 200:
                Map<String, NewCookie> cookies = response.getCookies();
                this.cookie = cookies.get("session").getValue();
        }

    }

    public void getSession() throws BaseFaradayException {

        log("Fetching session info");

        Response response = get("session", true);

        this.sessionInfo = response.readEntity(SessionInfo.class);

        Map<String, NewCookie> cookies = response.getCookies();
        if (cookies.containsKey("session")) {
            this.cookie = cookies.get("session").getValue();
        }

        log("Session set.");
        log(this.sessionInfo.toString());

    }

    private Response get(final String method, final boolean authenticated) throws FaradayConnectionException {
        WebTarget target = buildTargetForMethod(method);

        log("GET " + target.getUri().toString());

        try {
            Invocation.Builder request = target
                    .request(MediaType.APPLICATION_JSON);

            if (authenticated) {
                if (this.cookie == null) {
                    throw new IllegalStateException("Attempt to perform an authenticated request without a cookie.");
                }
                request = request.cookie("session", this.cookie);
            }

            return request.get();
        } catch (ProcessingException e) {
            e.printStackTrace(this.stdout);
            throw new FaradayConnectionException();
        }
    }

    public List<Workspace> getWorkspaces() throws BaseFaradayException {
        if (!this.urlIsValid) {
            throw new InvalidFaradayException();
        }

        Response response = get("v2/ws", true);

        Workspace[] workspaceList = response.readEntity(Workspace[].class);

        return Arrays.asList(workspaceList);
    }

    private Response get(final String method) throws FaradayConnectionException {
        return get(method, false);
    }

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
}

