package burp.faraday.models;

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

