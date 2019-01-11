package burp;

import burp.faraday.FaradayConnector;
import burp.faraday.FaradayExtensionUI;
import burp.faraday.VulnerabilityMapper;
import burp.faraday.models.ExtensionSettings;
import burp.faraday.models.vulnerability.Vulnerability;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import static burp.IContextMenuInvocation.*;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IScannerListener, IContextMenuFactory {

    private static final String EXTENSION_NAME = "Faraday for Burp v1.5";

    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;


    private IExtensionHelpers helpers;

    private FaradayConnector faradayConnector;
    private FaradayExtensionUI faradayExtensionUI;
    private ExtensionSettings extensionSettings;

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

    private void onSendVulnsToFaraday(IScanIssue[] issues) {
        if (issues == null) {
            return;
        }

        for (IScanIssue issue : issues) {
            Vulnerability vulnerability = VulnerabilityMapper.fromIssue(issue);
            faradayConnector.addVulnToWorkspace(vulnerability);
        }
    }

    private void onSendRequestsToFaraday(IHttpRequestResponse[] messages) {
        if (messages == null) {
            return;
        }

        for (IHttpRequestResponse message : messages) {
            Vulnerability vulnerability = VulnerabilityMapper.fromRequest(message);
            faradayConnector.addVulnToWorkspace(vulnerability);
        }
    }

    private void log(final String msg) {
        this.stdout.println("[EXTENDER] " + msg);
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        if (!extensionSettings.importNewVulns()) {
            return;
        }

        Vulnerability vulnerability = VulnerabilityMapper.fromIssue(issue);
        faradayConnector.addVulnToWorkspace(vulnerability);
    }
}

