/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.exceptions.http;

public class BadRequestException extends HTTPException {
    public BadRequestException() {
        super(400);
    }
}
