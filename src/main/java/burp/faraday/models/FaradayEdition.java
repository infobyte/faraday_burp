/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models;

public enum FaradayEdition {
    WHITE("w"), PINK("p"), BLACK("b");


    private final String editionName;

    FaradayEdition(String editionName) {

        this.editionName = editionName;
    }

    public String getEditionName() {
        return editionName;
    }

    public static FaradayEdition fromName(final String name) {
        for (FaradayEdition edition : FaradayEdition.values()) {
            if (edition.editionName.equals(name)) {
                return edition;
            }
        }

        return null;
    }
}
