package burp;

import burp.faraday.FaradayConnector;
import burp.faraday.FaradayExtensionUI;
import burp.faraday.VulnerabilityMapper;
import burp.faraday.models.ExtensionSettings;
import burp.faraday.models.vulnerability.Vulnerability;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
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

//        callbacks.registerScannerListener(this);
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
                if (invocation.getSelectedIssues().length > 0) {

                    menuItem = new JMenuItem("Send issue to Faraday", null);
                    menuItem.addActionListener(actionEvent -> onSendVulnsToFaraday(invocation.getSelectedIssues()));
                    menu.add(menuItem);
                }
                break;

            case CONTEXT_TARGET_SITE_MAP_TABLE:
            case CONTEXT_PROXY_HISTORY:
            case CONTEXT_MESSAGE_VIEWER_REQUEST:
                if (invocation.getSelectedMessages().length > 0) {
                    menuItem = new JMenuItem("Send request to Faraday", null);
                    menuItem.addActionListener(actionEvent -> onSendRequestsToFaraday(invocation.getSelectedMessages()));
                    menu.add(menuItem);
                }
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
//
//    private void eventScan(IContextMenuInvocation invocation, byte ctx) {
//        if (ctx == CONTEXT_SCANNER_RESULTS) {
//            IScanIssue[] invMessage = invocation.getSelectedIssues();
//
//            for (IScanIssue issue : invMessage) {
//                newScanIssue(issue, ctx, true);
//            }
//        } else {
//            IHttpRequestResponse[] invMessage = invocation.getSelectedMessages();
//
//            for (IHttpRequestResponse issue : invMessage) {
//                //newScanIssue(issue, ctx, true);
//            }
//        }
//    }
//
//    @Override
//    public void newScanIssue(IScanIssue issue) {
//        newScanIssue(issue, (byte) 0, false);
//    }
//
//    private void newScanIssue(IScanIssue issue, byte ctx, boolean do_import) {
//        if (!do_import && !importNewVulnsChkBox.isSelected()) {
//            //ignore new issues
//            return;
//        }
//
//        String host = issue.getUrl().getHost();
//        String port = String.valueOf(issue.getUrl().getPort());
//        URL url = issue.getUrl();
//        String resolution = "";
//
//        String ip;
//        try {
//            ip = InetAddress.getByName(issue.getHttpService().getHost()).getHostAddress();
//        } catch (Exception e) {
//            ip = host;
//        }
//
//        String issueName;
//        String severity;
//        StringBuilder desc = new StringBuilder();
//        if (ctx == CONTEXT_TARGET_SITE_MAP_TABLE || ctx == CONTEXT_PROXY_HISTORY || ctx == CONTEXT_MESSAGE_VIEWER_REQUEST) {
//            issueName = "Analyzing: ";
//            severity = "Information";
//            desc.append("This request was manually sent using burp");
//        } else {
//
//            if (issue.getIssueDetail() != null && !issue.getIssueDetail().isEmpty()) {
//                desc.append("Detail\n");
//                desc.append(issue.getIssueDetail());
//            }
//
//            String background = issue.getIssueBackground();
//            if (background!=null && !background.isEmpty()) {
//                desc.append("Background\n");
//                desc.append(background);
//            }
//
//            severity = issue.getSeverity();
//            issueName = issue.getIssueName();
//            resolution = issue.getRemediationBackground();
//
//            desc = new StringBuilder(desc.toString().replaceAll("<(/p|br/|/li|ul|ol)>", "\n").replaceAll("<li>", "* ").replaceAll("</?[^>]*>", ""));
//            resolution = resolution.replaceAll("<(/p|br/|/li)>", "\n").replaceAll("<li>", "* ").replaceAll("</?[^>]*>", "");
//        }
//
//        stdout.println("New scan issue host: " + host + ",name:" + issueName + ",IP:" + ip);
//
//
//        try {
//            faradayConnector.devlog("[BURP] New issue generation");
//            Integer hostId = (Integer) faradayConnector.execute("createAndAddHost", new Object[]{ip, "unknown", new String[]{host}});
//            Integer serviceId = (Integer) faradayConnector.execute("createAndAddServiceToInterface", new Object[]{hostId, "", issue.getUrl().getProtocol(), "tcp", new String[]{port}, "open"});
//
//            String path = "";
//            String response = "";
//            String request = "";
//            String method = "";
//            String param = "";
//
//            IRequestInfo req;
//            if (ctx == CONTEXT_TARGET_SITE_MAP_TABLE | ctx == CONTEXT_PROXY_HISTORY || ctx == CONTEXT_MESSAGE_VIEWER_REQUEST) {
//                req = helpers.analyzeRequest(issue.getHttpMessages()[0]);
//                param = getParam(req);
//                issueName += "(" + issue.getUrl().getPath().substring(0, 20) + ")";
//                path = issue.getUrl().toString();
//                request = helpers.bytesToString(issue.getHttpMessages()[0].getRequest());
//                method = req.getMethod();
//            } else {
//                if (issue.getHttpMessages() != null) {
//
//                    IHttpRequestResponse[] messages = issue.getHttpMessages();
//
//                    for (int i = 0; i < messages.length; i++) {
//
//                        IHttpRequestResponse m = messages[i];
//                        req = helpers.analyzeRequest(m.getRequest());
//                        if (i == 0) {
//                            path = req.getUrl().toString();
//                            request = helpers.bytesToString(m.getRequest());
//                            method = req.getMethod();
//                            response = helpers.bytesToString(m.getResponse());
//
//                            param = getParam(req);
//                        } else {
//                            desc.append("Request (").append(i).append("): ").append(req.getUrl());
//                        }
//                    }
//
//                    if (messages.length == 0) {
//                        path = issue.getUrl().toString();
//                    }
//
//                }
//            }
//
//            //createAndAddVulnWebToService(host_id, service_id, name, desc, ref, severity, resolution, website, path, request, response,method,pname, params,query,category):
//            Integer vulnId = (Integer) faradayConnector.execute("createAndAddVulnWebToService", new Object[]{hostId, serviceId, issueName,
//                    desc.toString(), new String[]{}, severity, resolution, host, path, request,
//                    response, method, "", param, "", ""});
//
//            stdout.println("Vulnerability created: " + vulnId);
//
//        } catch (XmlRpcException e) {
//            stdout.println("Error: " + e.code + " Message: " + e.getMessage());
//        }
//
//    }
//
//    @Override
//    public void extensionUnloaded() {
//        stdout.println("Extension was unloaded");
//    }
//
//        private String boolString(final String value) {
//        if (value.equals("0")) {
//            return "false";
//        }
//        return "true";
//    }
//
//    private String getParam(IRequestInfo request) {
//        StringBuilder param = new StringBuilder();
//
//        for (IParameter p : request.getParameters()) {
//            // TODO: Actually Get all parameters, cookies, jason, url, maybe we should get only url,get/post parameters
//            // http://portswigger.net/burp/extender/api/constant-values.html#burp.IParameter.PARAM_BODY
//
//            param.append(p.getType()).append(":").append(p.getName()).append("=").append(p.getValue()).append(",");
//        }
//
//        return param.toString();
//    }
//
//    private void restoreConfig() {
//        callbacks.saveExtensionSetting("first_run", "0");
//        callbacks.saveExtensionSetting("import_new_vulns", "1");
//        callbacks.saveExtensionSetting("rpc_server", "http://127.0.0.1:9876/");
//    }
//
//    private boolean isFirstRun() {
//        return callbacks.loadExtensionSetting("first_run") == null;
//    }
//
//    private void loadConfig() {
//        stdout.println("Loading configuration");
//
//        String importWasSelected = callbacks.loadExtensionSetting("import_new_vulns");
//
//        if (importWasSelected == null) {
//            importNewVulnsChkBox.setSelected(true);
//        } else {
//            importNewVulnsChkBox.setSelected(importWasSelected.equals("1"));
//        }
//
//        rpcServerTxt.setText(callbacks.loadExtensionSetting("rpc_server"));
//        if (rpcServerTxt.getText().trim().equals("")) {
//            rpcServerTxt.setText("http://127.0.0.1:9876/");
//        }
//
//        //Connect Rpc server
//        reconnect();
//
//        stdout.println("Config loaded");
//    }
//
//    private void saveConfig() {
//        callbacks.saveExtensionSetting("import_new_vulns", importNewVulnsChkBox.isSelected() ? "1" : "0");
//        callbacks.saveExtensionSetting("rpc_server", rpcServerTxt.getText());
//        stdout.println("Config saved.");
//    }
//
//    private void importVulns() {
//        //Get current vulnerabilities
//        stdout.println("Importing vulns.");
//
//        faradayConnector.devlog("[BURP] Importing issues");
//
//        for (IScanIssue issue : callbacks.getScanIssues(null)) {
//            newScanIssue(issue, CONTEXT_MESSAGE_EDITOR_RESPONSE, true);
//        }
//    }
//
//    private void reconnect() {
//        this.faradayConnector.reconnect(rpcServerTxt.getText());
//    }

    private void log(final String msg) {
        this.stdout.println("[EXTENDER] " + msg);
    }

    @Override
    public void newScanIssue(IScanIssue issue) {

    }
}

