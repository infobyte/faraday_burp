/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

package burp.faraday;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.ITab;
import burp.faraday.exceptions.*;
import burp.faraday.models.ExtensionSettings;
import burp.faraday.models.FaradayConnectorStatus;
import burp.faraday.models.vulnerability.Vulnerability;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class FaradayExtensionUI implements ITab {

    private JTextField faradayUrlText;
    private JTextField usernameText;
    private JPasswordField passwordField;
    private JTextField secondFactorField;
    private JButton statusButton;


    private JLabel loginStatusLabel;

    private JPanel tab;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private final FaradayConnector faradayConnector;
    private final ExtensionSettings extensionSettings;

    private Component loginPanel;
    private Component settingsPannel;
    private Component otherSettingsPanel;

    private JComboBox<Workspace> workspaceCombo;

    private FaradayConnectorStatus status = FaradayConnectorStatus.DISCONNECTED;

    public FaradayExtensionUI(PrintWriter stdout, IBurpExtenderCallbacks callbacks, FaradayConnector faradayConnector, ExtensionSettings extensionSettings) {
        this.stdout = stdout;
        this.callbacks = callbacks;
        this.faradayConnector = faradayConnector;
        this.extensionSettings = extensionSettings;

        this.tab = new JPanel();
        GroupLayout layout = new GroupLayout(this.tab);
        this.tab.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        this.loginPanel = setupLoginPanel();
        this.settingsPannel = setupSettingsPanel();
        this.otherSettingsPanel = setupOtherSettingsPanel();

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(loginPanel)
                        .addComponent(settingsPannel)
                        .addComponent(otherSettingsPanel)
        );

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(loginPanel)
                        .addComponent(settingsPannel)
                        .addComponent(otherSettingsPanel)
        );

        layout.linkSize(SwingConstants.HORIZONTAL, loginPanel, settingsPannel, otherSettingsPanel);

        disablePanel(settingsPannel);

        if (!extensionSettings.getCookie().isEmpty()) {
            log("Settings found:");
            log("Faraday Server URL: " + extensionSettings.getFaradayURL());
            log("Username: " + extensionSettings.getUsername());
            log("Cookie: " + extensionSettings.getCookie());
            log("Import new Vulns: " + extensionSettings.importNewVulns());

            faradayConnector.setBaseUrl(extensionSettings.getFaradayURL());
            faradayConnector.setCookie(extensionSettings.getCookie());
            try {
                faradayConnector.validateFaradayURL();
            } catch (InvalidFaradayException e) {
                JOptionPane.showMessageDialog(tab, "Faraday Server is down.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            } catch (ServerTooOldException e) {
                JOptionPane.showMessageDialog(tab, "Faraday server is too old to be used with this extension. Please upgrade to the latest version.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            getSession(false);
        }
    }

    private Component setupLoginPanel() {
        JPanel loginPanel = new JPanel();
        loginPanel.setBorder(BorderFactory.createTitledBorder("Login to Faraday"));

        JLabel faradayUrlLabel = new JLabel("Faraday Server URL: ");
        faradayUrlText = new JTextField();
        faradayUrlText.setText(extensionSettings.getFaradayURL());

        JLabel usernameLabel = new JLabel("Username: ");
        usernameText = new JTextField();
        usernameText.setEnabled(false);
        usernameText.setText(extensionSettings.getUsername());

        JLabel passwordLabel = new JLabel("Password: ");
        passwordField = new JPasswordField();
        passwordField.setEnabled(false);
        passwordField.setText(extensionSettings.getPassword());

        JLabel secondFactorLabel = new JLabel("2FA Token: ");
        secondFactorField = new JTextField();
        secondFactorField.setEnabled(false);

        statusButton = new JButton("Connect");
        statusButton.addActionListener(actionEvent -> onStatusPressed());

        loginStatusLabel = new JLabel("Not connected");

        GroupLayout layout = new GroupLayout(loginPanel);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        loginPanel.setLayout(layout);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(faradayUrlLabel)
                                .addComponent(usernameLabel)
                                .addComponent(passwordLabel)
                                .addComponent(secondFactorLabel)
                                .addComponent(statusButton)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(faradayUrlText, 256, 256, 256)
                                .addComponent(usernameText, 256, 256, 256)
                                .addComponent(passwordField, 256, 256, 256)
                                .addComponent(secondFactorField, 256, 256, 256)
                                .addComponent(loginStatusLabel)
                        )
        );

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(faradayUrlLabel)
                                .addComponent(faradayUrlText)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(usernameLabel)
                                .addComponent(usernameText)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(passwordLabel)
                                .addComponent(passwordField)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(secondFactorLabel)
                                .addComponent(secondFactorField)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(statusButton)
                                .addComponent(loginStatusLabel)
                        )
        );

        layout.linkSize(SwingConstants.VERTICAL, faradayUrlLabel, usernameLabel, passwordLabel, secondFactorLabel);
        layout.linkSize(SwingConstants.VERTICAL, faradayUrlText, usernameText, passwordField, secondFactorField);
        layout.linkSize(SwingConstants.HORIZONTAL, faradayUrlText, usernameText, passwordField, secondFactorField);

        return loginPanel;
    }

    private Component setupSettingsPanel() {
        JPanel settingsPannel = new JPanel();
        settingsPannel.setBorder(BorderFactory.createTitledBorder("Extension Settings"));
        JCheckBox inScopeCheckbox = new JCheckBox("Only in Burp scope");

        JCheckBox importNewVulnsCheckbox = new JCheckBox("Import new vulnerabilities automatically");
        importNewVulnsCheckbox.addItemListener(itemEvent -> extensionSettings.setImportNewVulns(itemEvent.getStateChange() == ItemEvent.SELECTED));
        importNewVulnsCheckbox.setSelected(extensionSettings.importNewVulns());

        JButton importCurrentVulnsButton = new JButton("Import current vulnerabilities");
        importCurrentVulnsButton.addActionListener(actionEvent -> onImportCurrentVulns(inScopeCheckbox.isSelected()));

        JLabel workspaceLabel = new JLabel("Active workspace: ");
        workspaceCombo = new JComboBox<>();
        workspaceCombo.setEnabled(false);

        workspaceCombo.addActionListener(actionEvent -> onWorkspaceSelected((Workspace) workspaceCombo.getSelectedItem()));

        GroupLayout layout = new GroupLayout(settingsPannel);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        settingsPannel.setLayout(layout);

        layout.setHorizontalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                        .addComponent(importNewVulnsCheckbox)
                        .addComponent(importCurrentVulnsButton)
                        .addComponent(workspaceLabel)
                )
                .addGroup(layout.createParallelGroup()
                        .addComponent(inScopeCheckbox)
                        .addComponent(workspaceCombo)
                )
        );

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addComponent(importNewVulnsCheckbox)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(importCurrentVulnsButton)
                        .addComponent(inScopeCheckbox)
                )
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(workspaceLabel)
                        .addComponent(workspaceCombo, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                )

        );

        return settingsPannel;
    }

    private Component setupOtherSettingsPanel() {
        JPanel otherSettingsPanel = new JPanel();
        otherSettingsPanel.setBorder(BorderFactory.createTitledBorder("Other Settings"));

        JButton restoreButton = new JButton("Restore Settings");
        restoreButton.addActionListener(actionEvent -> restoreSettings());

        GroupLayout layout = new GroupLayout(otherSettingsPanel);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        otherSettingsPanel.setLayout(layout);

        layout.setHorizontalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                        .addComponent(restoreButton)
                )
        );

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addComponent(restoreButton)
        );


        return otherSettingsPanel;
    }

    private void onStatusPressed() {
        switch (this.status) {
            case DISCONNECTED:
                connect();
                break;
            case CONNECTED:
                login(false);
                break;
            case NEEDS_2FA:
                verifyToken();
                break;
            case LOGGED_IN:
                logout();
                break;
        }
    }

    private void login(boolean isSecondAttempt) {
        String username = usernameText.getText().trim();

        if (username.isEmpty()) {
            JOptionPane.showMessageDialog(tab, "Username is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String password = new String(passwordField.getPassword()).trim();

        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(tab, "Password is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            faradayConnector.login(username, password);
        } catch (InvalidCredentialsException e) {

            JOptionPane.showMessageDialog(tab, "Invalid credentials.", "Error", JOptionPane.ERROR_MESSAGE);
            passwordField.setText("");
            setStatus("Invalid credentials");
            return;

        } catch (SecondFactorRequiredException e) {

            secondFactorField.setEnabled(true);
            setStatus("2FA Token required");
            statusButton.setText("Verify Token");

            usernameText.setEditable(false);
            passwordField.setEditable(false);
            extensionSettings.setUsername(username);
            secondFactorField.setEditable(true);

            JOptionPane.showMessageDialog(tab, "The 2FA token is required", "Error", JOptionPane.INFORMATION_MESSAGE);
            this.status = FaradayConnectorStatus.NEEDS_2FA;
            return;

        } catch (InvalidFaradayException e) {

            JOptionPane.showMessageDialog(tab, "Invalid Faraday server URL.", "Error", JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
            return;

        } catch (BaseFaradayException e) {
            // Unreachable
            e.printStackTrace();
            return;
        }

        extensionSettings.setUsername(username);
        JOptionPane.showMessageDialog(tab, "Login successful!", "Logged in", JOptionPane.INFORMATION_MESSAGE);

        getSession(isSecondAttempt);
    }

    private void verifyToken() {
        String token = secondFactorField.getText().trim();

        if (token.isEmpty()) {
            JOptionPane.showMessageDialog(tab, "Token is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            faradayConnector.verify2FAToken(token);
        } catch (InvalidCredentialsException e) {
            log("Error when validating token");
            JOptionPane.showMessageDialog(tab, "Invalid token.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        } catch (BaseFaradayException e) {
            e.printStackTrace(stdout);
        }

        JOptionPane.showMessageDialog(tab, "Login successful!", "Logged in", JOptionPane.INFORMATION_MESSAGE);
        secondFactorField.setEditable(false);
        getSession(false);
    }

    private void getSession(boolean isSecondAttempt) {

        try {
            faradayConnector.getSession();
        } catch (CookieExpiredException e) {
//            extensionSettings.resetCookie();
            if (isSecondAttempt) {
                log("Unable to renew the cookie.");
                return;
            }
            login(true);
            log("The session cookie has expired. Please login again.");
            return;
        } catch (BaseFaradayException e) {
            log("Error acquiring session");
            log(e.toString());
            return;
        }

        faradayUrlText.setEditable(false);
        usernameText.setEditable(false);
        passwordField.setEditable(false);

        statusButton.setText("Logout");
        setStatus("Logged in");
        this.status = FaradayConnectorStatus.LOGGED_IN;
        loadWorkspaces();
        enablePanel(settingsPannel);

        extensionSettings.setUsername(usernameText.getText());
        extensionSettings.setPassword(new String(passwordField.getPassword()).trim());
        extensionSettings.setFaradayURL(faradayUrlText.getText());
        extensionSettings.setCookie(faradayConnector.getCookie());
    }

    private void connect() {
        String faradayUrl = faradayUrlText.getText().trim();

        if (faradayUrl.isEmpty()) {
            JOptionPane.showMessageDialog(tab, "Faraday URL is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        faradayConnector.setBaseUrl(faradayUrl);

        try {
            faradayConnector.validateFaradayURL();
        } catch (InvalidFaradayException e) {
            JOptionPane.showMessageDialog(tab, "Faraday URL is not a valid Faraday server.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        } catch (ServerTooOldException e) {
            JOptionPane.showMessageDialog(tab, "Faraday server is too old to be used with this extension. Please upgrade to the latest version.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        usernameText.setEnabled(true);
        passwordField.setEnabled(true);
        statusButton.setText("Login");

        faradayUrlText.setEditable(false);
        setStatus("Connected");
        this.status = FaradayConnectorStatus.CONNECTED;
    }

    private void logout() {
        faradayUrlText.setEditable(true);
        usernameText.setEditable(true);
        passwordField.setEditable(true);
        passwordField.setText("");

        secondFactorField.setEnabled(false);
        secondFactorField.setText("");

        setStatus("Not connected");

        statusButton.setText("Connect");
        this.status = FaradayConnectorStatus.DISCONNECTED;

        faradayConnector.logout();
        extensionSettings.resetCookie();
        workspaceCombo.removeAllItems();
        disablePanel(settingsPannel);
    }

    private void restoreSettings() {
        logout();
        extensionSettings.restore();
        faradayUrlText.setText(extensionSettings.getDefaultFaradayUrl());
    }

    private void loadWorkspaces() {
        String currentWorkspaceName = extensionSettings.getCurrentWorkspace();

        workspaceCombo.removeAllItems();

        try {
            List<Workspace> workspaceList = faradayConnector.getWorkspaces();
            workspaceList.forEach(workspaceCombo::addItem);

            if (!currentWorkspaceName.isEmpty()) {
                workspaceList.stream()
                        .filter(workspace -> workspace.getName().equals(currentWorkspaceName))
                        .findFirst()
                        .ifPresent(workspace -> workspaceCombo.setSelectedItem(workspace));
            }


        } catch (BaseFaradayException e) {
            log("Could not fetch workspaces: " + e);
        }
    }

    private void onWorkspaceSelected(Workspace workspace) {
        if (workspace == null) {
            return;
        }
        faradayConnector.setCurrentWorkspace(workspace);
        extensionSettings.setCurrentWorkspace(workspace.getName());
    }

    private void onImportCurrentVulns(boolean onlyInScope) {
        runInThread(() -> {

            List<IScanIssue> issues = Arrays.asList(callbacks.getScanIssues(null));

            if (onlyInScope) {
                issues = issues.stream().filter(issue -> callbacks.isInScope(issue.getUrl())).collect(Collectors.toList());
            }

            final List<Vulnerability> vulnerabilities = issues.stream().map(VulnerabilityMapper::fromIssue).collect(Collectors.toList());

            for (Vulnerability vulnerability : vulnerabilities) {
                if (!addVulnerability(vulnerability)) {
                    break;
                }
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "Faraday";
    }

    @Override
    public Component getUiComponent() {
        return this.tab;
    }

    private void setStatus(final String status) {
        loginStatusLabel.setText(status);
    }

    private void log(final String msg) {
        this.stdout.println("[UI] " + msg);
    }

    private void disablePanel(Component panel) {
        Arrays.stream(((Container) panel).getComponents()).forEach(component -> component.setEnabled(false));
        panel.setEnabled(false);
    }

    private void enablePanel(Component panel) {
        Arrays.stream(((Container) panel).getComponents()).forEach(component -> component.setEnabled(true));
        panel.setEnabled(true);
    }

    private void showErrorAlert(final String message) {
        log(message);
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(tab, message, "Error", JOptionPane.ERROR_MESSAGE));
    }

    public boolean addVulnerability(final Vulnerability vulnerability) {

        try {
            faradayConnector.addVulnToWorkspace(vulnerability);
        } catch (ObjectNotCreatedException e) {
            log("Unable to create object tree");
            showErrorAlert("There was an error creating the objects.");
            e.printStackTrace(stdout);
            return false;
        } catch (InvalidFaradayException e) {
            showErrorAlert("Could not connect to Faraday Server. Please check that it is running and that you are authenticated.");
            return false;
        }

        return true;
    }

    public void runInThread(final Runnable runnable) {
        new SwingWorker<Void, Void>() {

            @Override
            protected Void doInBackground() {
                runnable.run();

                return null;
            }
        }.execute();
    }

}
