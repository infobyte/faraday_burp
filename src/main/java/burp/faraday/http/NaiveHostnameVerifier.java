package burp.faraday.http;

import javax.net.ssl.*;
import java.util.*;


public class NaiveHostnameVerifier implements HostnameVerifier {
    private final Set<String> naivelyTrustedHostnames;
    private final HostnameVerifier hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
    public NaiveHostnameVerifier(final String... naivelyTrustedHostnames) {
        this.naivelyTrustedHostnames = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(naivelyTrustedHostnames)));
    }
    @Override
    public boolean verify(final String hostname, final SSLSession session) {
        return this.naivelyTrustedHostnames.contains(hostname) ||
                this.hostnameVerifier.verify(hostname, session);
    }
}