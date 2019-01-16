/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.exceptions.http;

import burp.faraday.models.responses.ExistingObjectEntity;

public class ConflictException extends HTTPException {

    private final ExistingObjectEntity existingObject;

    public ConflictException(ExistingObjectEntity existingObject) {
        super(409);
        this.existingObject = existingObject;
    }

    public ExistingObjectEntity getExistingObject() {
        return existingObject;
    }
}
