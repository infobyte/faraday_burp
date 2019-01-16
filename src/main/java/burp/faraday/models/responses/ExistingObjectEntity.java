/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.responses;

public class ExistingObjectEntity {
    private CreatedObjectEntity object;

    public ExistingObjectEntity() {
    }

    public CreatedObjectEntity getObject() {
        return object;
    }

    public void setObject(CreatedObjectEntity object) {
        this.object = object;
    }

    @Override
    public String toString() {
        return "ExistingObjectEntity{" +
                "object=" + object +
                '}';
    }
}

