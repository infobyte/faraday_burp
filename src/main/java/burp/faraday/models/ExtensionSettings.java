/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models;

import burp.IBurpExtenderCallbacks;

public class ExtensionSettings {

    private final IBurpExtenderCallbacks callbacks;

    private static final String DEFAULT_FARADAY_URL = "http://127.0.0.1:5985";
    private static final String DEFAULT_IMPORT_NEW_VULNS = "0";

    private static final String KEY_FARADAY_URL = "faraday_url";
    private static final String KEY_USERNAME = "faraday_username";
    private static final String KEY_PASSWORD = "faraday_password";
    private static final String KEY_CURRENT_WORKSPACE = "faraday_current_workspace";
    private static final String KEY_IMPORT_NEW_VULNS = "faraday_import_new";


    public ExtensionSettings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public String getFaradayURL() {
        return getSetting(KEY_FARADAY_URL, DEFAULT_FARADAY_URL);
    }

    public void setFaradayURL(String faradayURL) {
        if (faradayURL != null) {
            faradayURL = faradayURL.trim();
        }
        callbacks.saveExtensionSetting(KEY_FARADAY_URL, faradayURL);
    }

    public String getUsername() {
        return getSetting(KEY_USERNAME);
    }

    public void setUsername(String username) {
        if (username != null) {
            username = username.trim();
        }
        callbacks.saveExtensionSetting(KEY_USERNAME, username);
    }

    public String getPassword() {
        return getSetting(KEY_PASSWORD);
    }

    public void setPassword(String password) {
        if (password != null) {
            password = password.trim();
        }
        callbacks.saveExtensionSetting(KEY_PASSWORD, password);
    }

    public String getCurrentWorkspace() {
        return getSetting(KEY_CURRENT_WORKSPACE);
    }

    public void setCurrentWorkspace(String currentWorkspace) {
        if (currentWorkspace != null) {
            currentWorkspace = currentWorkspace.trim();
        }

        callbacks.saveExtensionSetting(KEY_CURRENT_WORKSPACE, currentWorkspace);
    }

    public boolean importNewVulns() {
        return getSetting(KEY_IMPORT_NEW_VULNS, DEFAULT_IMPORT_NEW_VULNS).equals("1");
    }

    public void setImportNewVulns(boolean importNewVulns) {
        callbacks.saveExtensionSetting(KEY_IMPORT_NEW_VULNS, importNewVulns ? "1" : "0");
    }

    public void restore() {
        callbacks.saveExtensionSetting(KEY_FARADAY_URL, DEFAULT_FARADAY_URL);
        callbacks.saveExtensionSetting(KEY_USERNAME, "");
        callbacks.saveExtensionSetting(KEY_PASSWORD, "");
        callbacks.saveExtensionSetting(KEY_CURRENT_WORKSPACE, "");
        callbacks.saveExtensionSetting(KEY_IMPORT_NEW_VULNS, "0");
    }

    private String getSetting(final String key) {
        return getSetting(key, "");
    }

    private String getSetting(final String key, final String defaultValue) {
        String value = callbacks.loadExtensionSetting(key);

        if (value == null) {
            return defaultValue;
        }

        value = value.trim();

        if (value.isEmpty()) {
            return defaultValue;
        }

        return value;
    }

    public String getDefaultFaradayUrl() {
        return DEFAULT_FARADAY_URL;
    }

}
