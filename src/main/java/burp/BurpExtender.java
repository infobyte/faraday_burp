/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp;

import burp.faraday.FaradayConnector;
import burp.faraday.FaradayExtensionUI;
import burp.faraday.VulnerabilityMapper;
import burp.faraday.models.Workspace;
import burp.faraday.exceptions.InvalidCredentialsException;
import burp.faraday.exceptions.InvalidFaradayServerException;
import burp.faraday.exceptions.SecondFactorRequiredException;
import burp.faraday.exceptions.ServerTooOldException;
import burp.faraday.models.ExtensionSettings;
import burp.faraday.models.vulnerability.Vulnerability;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static burp.IContextMenuInvocation.*;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IScannerListener, IContextMenuFactory {

    private static final String EXTENSION_VERSION = "2.6";

    private static final String EXTENSION_NAME = "Faraday plugin for Burp (v: " + EXTENSION_VERSION + ")";

    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;


    private IExtensionHelpers helpers;

    private FaradayConnector faradayConnector;
    private FaradayExtensionUI faradayExtensionUI;
    private ExtensionSettings extensionSettings;

    /**
     * This method will be called by Burp to load the extension into the GUI.
     * <p>
     * We should read the settings, connect and login if necessary, and register ourselves for
     * Burp events.
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(EXTENSION_NAME);

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        VulnerabilityMapper.setHelpers(helpers);

        stdout = new PrintWriter(callbacks.getStdout(), true);
        this.faradayConnector = new FaradayConnector(stdout);
        this.extensionSettings = new ExtensionSettings(callbacks);
        this.faradayExtensionUI = new FaradayExtensionUI(stdout, callbacks, faradayConnector, extensionSettings);

        if (!extensionSettings.getUsername().isEmpty() && !extensionSettings.getPassword().isEmpty()) {

            // We found the username and password saved in the settings. That's all we need to authenticate.

            log("Settings found");
            log("Faraday Server URL: " + extensionSettings.getFaradayURL());
            log("Username: " + extensionSettings.getUsername());
            log("Import new Vulns: " + extensionSettings.importNewVulns());

            faradayConnector.setBaseUrl(extensionSettings.getFaradayURL(), extensionSettings.ignoreSSLErrors());
            try {
                faradayConnector.validateFaradayURL();
            } catch (InvalidFaradayServerException e) {
                faradayExtensionUI.showErrorAlert("Faraday Server is down.");
            } catch (ServerTooOldException e) {
                faradayExtensionUI.showErrorAlert("Faraday server is too old to be used with this extension. Please upgrade to the latest version.");
            }

            try {

                faradayConnector.login(extensionSettings.getUsername(), extensionSettings.getPassword());
                faradayExtensionUI.notifyLoggedIn(false);

            } catch (SecondFactorRequiredException e) {

                faradayExtensionUI.showInfoAlert("The 2FA token for Faraday is required");
                faradayExtensionUI.notify2FATokenNeeded();

            } catch (InvalidCredentialsException e) {

                faradayExtensionUI.showErrorAlert("Invalid credentials.");

            } catch (InvalidFaradayServerException e) {

                faradayExtensionUI.showErrorAlert("Faraday Server is down.");

            }
        }

        callbacks.addSuiteTab(faradayExtensionUI);

        log(EXTENSION_NAME + " Loaded");

        callbacks.registerScannerListener(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        log("Unloading extension");
        faradayConnector.logout();

    }

    /**
     * Callback used to add menu items.
     * <p>
     * We will add an item in the scanner results and the request lists.
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final ArrayList<JMenuItem> menu = new ArrayList<>();

        // Which part of the interface the user selects
        byte ctx = invocation.getInvocationContext();

        JMenuItem menuItem;
        switch (ctx) {
            case CONTEXT_SCANNER_RESULTS:
                menuItem = new JMenuItem("Send issue to Faraday", null);
                menuItem.addActionListener(actionEvent -> onSendVulnsToFaraday(invocation.getSelectedIssues()));
                menu.add(menuItem);

                break;
            case CONTEXT_INTRUDER_ATTACK_RESULTS:
            case CONTEXT_MESSAGE_EDITOR_REQUEST:
            case CONTEXT_SEARCH_RESULTS:
            case CONTEXT_TARGET_SITE_MAP_TABLE:
            case CONTEXT_PROXY_HISTORY:
            case CONTEXT_MESSAGE_VIEWER_REQUEST:
                menuItem = new JMenuItem("Send request to Faraday", null);
                menuItem.addActionListener(actionEvent -> onSendRequestsToFaraday(invocation.getSelectedMessages()));
                menu.add(menuItem);

                break;
        }

        return menu;
    }

    /**
     * The user has requested to import a list of issues to Faraday.
     *
     * @param issues The list of issues to import
     */
    private void onSendVulnsToFaraday(IScanIssue[] issues) {
        if (issues == null) {
            return;
        }

        // Run the import on a separate thread
        FaradayExtensionUI.runInThread(() -> {
            final List<Vulnerability> vulnerabilities = Arrays.stream(issues).map(VulnerabilityMapper::fromIssue).collect(Collectors.toList());
            int vuln_count = vulnerabilities.size();
            int created_vulns = 0;
            final Workspace workspace = faradayConnector.getCurrentWorkspace();
            this.faradayExtensionUI.setStatus("Sending " + vuln_count + " vulnerabilities...");
            log("Sending " + vuln_count + " vulnerabilities...");
            this.faradayExtensionUI.addMessage("Sending " + vuln_count + " vulnerabilities...");
            for (Vulnerability vulnerability : vulnerabilities) {
                if (faradayExtensionUI.addVulnerability(vulnerability, workspace)) {
                    this.faradayExtensionUI.addMessage("Created Vulnerability");
                    created_vulns ++;
                }
            }
            String message = "Created " + created_vulns + " of " + vuln_count + " Vulnerabilities";
            if (created_vulns != vuln_count){
                this.faradayExtensionUI.showErrorAlert(message);
            }else{
                this.faradayExtensionUI.showInfoAlert(message);
            }

            this.faradayExtensionUI.setStatus(message);
        });
    }

    /**
     * The user has requested to import a list of requests to Faraday.
     *
     * @param messages The list of requests to import
     */
    private void onSendRequestsToFaraday(IHttpRequestResponse[] messages) {
        if (messages == null) {
            return;
        }

        // Run the import on a separate thread
        FaradayExtensionUI.runInThread(() -> {
            final List<Vulnerability> vulnerabilities = Arrays.stream(messages).map(VulnerabilityMapper::fromRequest).collect(Collectors.toList());
            int vuln_count = vulnerabilities.size();
            int created_vulns = 0;
            final Workspace workspace = faradayConnector.getCurrentWorkspace();
            this.faradayExtensionUI.setStatus("Sending " + vuln_count + " requests..." );
            log("Sending " + vuln_count + " requests...");
            this.faradayExtensionUI.addMessage("Sending " + vuln_count + " requests...");
            for (Vulnerability vulnerability : vulnerabilities) {
                if (faradayExtensionUI.addVulnerability(vulnerability, workspace)) {
                    this.faradayExtensionUI.addMessage("Created Request");
                    created_vulns ++;
                }
            }
            String message = "Created " + created_vulns + " of " + vuln_count + " requests";
            if (created_vulns != vuln_count){
                this.faradayExtensionUI.showErrorAlert(message);
            }else{
                this.faradayExtensionUI.showInfoAlert(message);
            }

            this.faradayExtensionUI.setStatus(message);
        });
    }

    private void log(final String msg) {
        this.stdout.println("[EXTENDER] " + msg);
    }

    /**
     * Callback for when an issue is added to the scanner results.
     *
     * @param issue The issue just added.
     */
    @Override
    public void newScanIssue(IScanIssue issue) {
        if (!extensionSettings.importNewVulns()) {
            // The user has the automatic imports turned off.
            return;
        }

        //Run the import on a separate thread
        FaradayExtensionUI.runInThread(() -> {
            final Workspace workspace = faradayConnector.getCurrentWorkspace();
            final Vulnerability vulnerability = VulnerabilityMapper.fromIssue(issue);
            faradayExtensionUI.addVulnerability(vulnerability, workspace);
        });
    }


}

