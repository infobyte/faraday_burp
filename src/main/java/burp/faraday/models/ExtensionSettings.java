/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday.models;

import burp.IBurpExtenderCallbacks;

import java.util.Objects;

/**
 * This class allows tracking the settings of the extension, and
 * provides an easy way of modifying the values o resetting them.
 */
public class ExtensionSettings {

    /**
     * The callbacks will be used to write the changes into the burp settings store.
     */
    private final IBurpExtenderCallbacks callbacks;

    private static final String DEFAULT_FARADAY_URL = "http://127.0.0.1:5985";
    private static final String DEFAULT_IMPORT_NEW_VULNS = "0";
    private static final String DEFAULT_IGNORE_SSL_ERRORS = "0";

    private static final String KEY_FARADAY_URL = "faraday_url";
    private static final String KEY_USERNAME = "faraday_username";
    private static final String KEY_PASSWORD = "faraday_password";
    private static final String KEY_CURRENT_WORKSPACE = "faraday_current_workspace";
    private static final String KEY_IMPORT_NEW_VULNS = "faraday_import_new";
    private static final String KEY_IGNORE_SSL_ERRORS = "faraday_ignore_ssl_errors";


    public ExtensionSettings(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * Fetches the current Faraday Server URL, or the default one of none is set
     */
    public String getFaradayURL() {
        return getSetting(KEY_FARADAY_URL, DEFAULT_FARADAY_URL);
    }

    /**
     * Sets the Faraday Server URL.
     *
     * @param faradayURL The URL used to connect to Faraday Server
     */
    public void setFaradayURL(String faradayURL) {
        Objects.requireNonNull(faradayURL);
        callbacks.saveExtensionSetting(KEY_FARADAY_URL, faradayURL.trim());
    }

    /**
     * Fetches the current username.
     *
     * @return The current username, or an empty String if not set.
     */
    public String getUsername() {
        return getSetting(KEY_USERNAME);
    }

    /**
     * Sets the username used to login to the Faraday Server.
     *
     * @param username The username used to login.
     */
    public void setUsername(String username) {
        Objects.requireNonNull(username);
        callbacks.saveExtensionSetting(KEY_USERNAME, username.trim());
    }

    /**
     * Fetches the current password.
     *
     * @return The current password, or an empty String if not set.
     */
    public String getPassword() {
        return getSetting(KEY_PASSWORD);
    }

    /**
     * Sets the current password.
     *
     * @param password The password used to login.
     */
    public void setPassword(String password) {
        Objects.requireNonNull(password);
        callbacks.saveExtensionSetting(KEY_PASSWORD, password);
    }

    /**
     * Fetches the current workspace.
     *
     * @return The current workspace, or an empty String if not set.
     */
    public String getCurrentWorkspace() {
        return getSetting(KEY_CURRENT_WORKSPACE);
    }

    /**
     * Sets the current workspace.
     *
     * @param currentWorkspace The workspace used from now on to create objects.
     */
    public void setCurrentWorkspace(String currentWorkspace) {
        Objects.requireNonNull(currentWorkspace);
        callbacks.saveExtensionSetting(KEY_CURRENT_WORKSPACE, currentWorkspace.trim());
    }

    /**
     * Fetches the setting on whether to import new vulns or not.
     *
     * @return A boolean value with the current setting.
     */
    public boolean importNewVulns() {
        return getSetting(KEY_IMPORT_NEW_VULNS, DEFAULT_IMPORT_NEW_VULNS).equals("1");
    }

    /**
     * Sets the setting on new vulns importing.
     *
     * @param importNewVulns Whether to automatically import new vulns or not.
     */
    public void setImportNewVulns(boolean importNewVulns) {
        callbacks.saveExtensionSetting(KEY_IMPORT_NEW_VULNS, importNewVulns ? "1" : "0");
    }

    /**
     * Fetches the setting on whether to ignore ssl errors.
     *
     * @return A boolean value with the current setting.
     */
    public boolean ignoreSSLErrors() {
        return getSetting(KEY_IGNORE_SSL_ERRORS, DEFAULT_IGNORE_SSL_ERRORS).equals("1");
    }

    /**
     * Sets the setting on ignore ssl errors.
     *
     * @param importNewVulns Whether to automatically import new vulns or not.
     */
    public void setIgnoreSSLErrors(boolean ignoreSSlErrors) {
        callbacks.saveExtensionSetting(KEY_IGNORE_SSL_ERRORS, ignoreSSlErrors ? "1" : "0");
    }


    /**
     * Restores all settings to default values.
     */
    public void restore() {
        callbacks.saveExtensionSetting(KEY_FARADAY_URL, DEFAULT_FARADAY_URL);
        callbacks.saveExtensionSetting(KEY_USERNAME, "");
        callbacks.saveExtensionSetting(KEY_PASSWORD, "");
        callbacks.saveExtensionSetting(KEY_CURRENT_WORKSPACE, "");
        callbacks.saveExtensionSetting(KEY_IMPORT_NEW_VULNS, "0");
        callbacks.saveExtensionSetting(KEY_IGNORE_SSL_ERRORS, "0");
    }

    /**
     * Fetches the desired setting, defaulting to an empty string if not found.
     *
     * @param key The setting to fetch
     *
     * @return The value of the setting, or an empty string if not set.
     */
    private String getSetting(final String key) {
        return getSetting(key, "");
    }

    /**
     * Fetches the desired setting, defaulting to the defaultValue param if not found.
     *
     * @param key          The setting to fetch.
     * @param defaultValue The value to return if not found.
     *
     * @return The value of the setting, or defaultValue if not set.
     */
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

    /**
     * Helper method to return the default value of the Faraday Server URL
     */
    public String getDefaultFaradayUrl() {
        return DEFAULT_FARADAY_URL;
    }

}
