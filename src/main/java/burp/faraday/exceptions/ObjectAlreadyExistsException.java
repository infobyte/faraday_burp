package burp.faraday.exceptions;

import burp.faraday.models.ExistingObjectEntity;

public class ObjectAlreadyExistsException extends Exception {

    private final ExistingObjectEntity existingObjectEntity;

    public ObjectAlreadyExistsException(ExistingObjectEntity readEntity) {
        this.existingObjectEntity = readEntity;
    }

    public ExistingObjectEntity getExistingObjectEntity() {
        return existingObjectEntity;
    }
}
