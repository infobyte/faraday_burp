package burp.faraday.http;
import feign.Client;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import burp.faraday.http.NaiveHostnameVerifier;
import burp.faraday.http.NaiveSSLSocketFactory;

public class FeignClientConfiguration {

    public static Client client(String host) throws NoSuchAlgorithmException, KeyManagementException {
        return new Client.Default(new NaiveSSLSocketFactory(host),
                new NaiveHostnameVerifier(host));
    }
}