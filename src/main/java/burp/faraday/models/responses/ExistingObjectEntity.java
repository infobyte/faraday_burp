/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.responses;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ExistingObjectEntity {
    private ExistingObject object;

    public ExistingObjectEntity() {
    }

    public ExistingObject getObject() {
        return object;
    }

    public void setObject(ExistingObject object) {
        this.object = object;
    }

    @Override
    public String toString() {
        return "ExistingObjectEntity{" +
                "object=" + object +
                '}';
    }
}

