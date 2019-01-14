/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.requests;

public class SecondFactor {

    private String secret;

    public SecondFactor() {

    }

    public SecondFactor(String secret) {
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    @Override
    public String toString() {
        return "SecondFactor{" +
                "secret='" + secret + '\'' +
                '}';
    }
}
