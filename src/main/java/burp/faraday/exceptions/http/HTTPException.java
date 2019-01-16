/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.exceptions.http;

public class HTTPException extends Exception {
    private final int code;

    public HTTPException(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
