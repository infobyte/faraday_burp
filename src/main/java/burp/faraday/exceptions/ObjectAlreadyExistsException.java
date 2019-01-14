/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.exceptions;

import burp.faraday.models.responses.ExistingObjectEntity;

public class ObjectAlreadyExistsException extends Exception {

    private final ExistingObjectEntity existingObjectEntity;

    public ObjectAlreadyExistsException(ExistingObjectEntity readEntity) {
        this.existingObjectEntity = readEntity;
    }

    public ExistingObjectEntity getExistingObjectEntity() {
        return existingObjectEntity;
    }
}
