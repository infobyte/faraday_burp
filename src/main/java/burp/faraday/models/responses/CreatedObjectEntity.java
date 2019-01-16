/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models.responses;

import com.google.gson.annotations.SerializedName;

public class CreatedObjectEntity {

    @SerializedName("_id")
    private int id;

    public CreatedObjectEntity() {

    }

    public CreatedObjectEntity(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "CreatedObjectEntity{" +
                "id=" + id +
                '}';
    }
}
