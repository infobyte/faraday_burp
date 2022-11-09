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
import burp.faraday.models.Workspace;
import burp.faraday.models.vulnerability.Vulnerability;
import burp.faraday.models.vulnerability.Command;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.text.SimpleDateFormat;
import java.util.HashMap;

/**
 * This class will be responsible of drawing the UI of the extension inside Burp
 */
public class FaradayExtensionUI implements ITab {

    private JTextField faradayUrlText;
    private JTextField usernameText;
    private JPasswordField passwordField;
    private JTextField secondFactorField;
    private JTextField newWorkspaceText;
    private JButton statusButton;
    private JCheckBox ignoreSSLErrorsCheckbox;
    private JLabel placeHolderLabel;

    private JLabel loginStatusLabel;
    private JLabel statusLabel;
    private JTextArea messagesTextArea;

    private JPanel tab;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private final FaradayConnector faradayConnector;
    private final ExtensionSettings extensionSettings;

    private Component loginPanel;
    private Component settingsPannel;
    private Component otherSettingsPanel;
    private Component statusPanel;
    private Component newWorkspacePanel;
    private Component messagesPanel;
    private HashMap<Integer, Integer> commandsMap = null;

    private JComboBox<Workspace> workspaceCombo;

    private FaradayConnectorStatus status = FaradayConnectorStatus.DISCONNECTED;

    public FaradayExtensionUI(PrintWriter stdout, IBurpExtenderCallbacks callbacks, FaradayConnector faradayConnector, ExtensionSettings extensionSettings, HashMap<Integer, Integer> commandsMap) {
        this.stdout = stdout;
        this.callbacks = callbacks;
        this.faradayConnector = faradayConnector;
        this.extensionSettings = extensionSettings;

        this.tab = new JPanel();
        GroupLayout layout = new GroupLayout(this.tab);
        this.tab.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        // Initialize the three panels and arrange them in a vertical layout
        this.loginPanel = setupLoginPanel();
        this.settingsPannel = setupSettingsPanel();
        this.otherSettingsPanel = setupOtherSettingsPanel();
        this.statusPanel = setupStatusPanel();
        this.newWorkspacePanel  = setupNewWorkspacePanel();
        this.messagesPanel = setupMessagesPanel();

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(loginPanel)
                                .addComponent(settingsPannel)
                                .addComponent(otherSettingsPanel)
                                .addComponent(statusPanel)
                                .addComponent(newWorkspacePanel)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(messagesPanel)

                        )


        );

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(loginPanel)
                                        .addComponent(settingsPannel)
                                        .addComponent(newWorkspacePanel)
                                        .addComponent(otherSettingsPanel)
                                        .addComponent(statusPanel)
                                )
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(messagesPanel)
                                )
                        )
        );

        layout.linkSize(SwingConstants.HORIZONTAL, loginPanel, settingsPannel, otherSettingsPanel, statusPanel);
        disablePanel(settingsPannel);
        this.commandsMap = commandsMap;
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

        ignoreSSLErrorsCheckbox = new JCheckBox("Ignore SSL Errors");
        ignoreSSLErrorsCheckbox.addItemListener(itemEvent -> extensionSettings.setIgnoreSSLErrors(itemEvent.getStateChange() == ItemEvent.SELECTED));
        ignoreSSLErrorsCheckbox.setSelected(extensionSettings.ignoreSSLErrors());
        JLabel placeHolderLabel = new JLabel("   ");
        loginStatusLabel = new JLabel("Not connected");
        Font f = loginStatusLabel.getFont();
        loginStatusLabel.setFont(f.deriveFont(f.getStyle() | Font.BOLD));

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
                                .addComponent(placeHolderLabel)
                                .addComponent(placeHolderLabel)
                                .addComponent(statusButton)

                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(faradayUrlText, 256, 256, 256)
                                .addComponent(usernameText, 256, 256, 256)
                                .addComponent(passwordField, 256, 256, 256)
                                .addComponent(secondFactorField, 256, 256, 256)
                                .addComponent(ignoreSSLErrorsCheckbox, 256, 256, 256)
                                .addComponent(placeHolderLabel)
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
                                .addComponent(placeHolderLabel)
                                .addComponent(ignoreSSLErrorsCheckbox)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(placeHolderLabel)
                                .addComponent(placeHolderLabel)
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
        JSeparator componentsSeparator = new JSeparator(SwingConstants.VERTICAL);

        JCheckBox importNewVulnsCheckbox = new JCheckBox("Auto import new vulnerabilities");
        importNewVulnsCheckbox.addItemListener(itemEvent -> extensionSettings.setImportNewVulns(itemEvent.getStateChange() == ItemEvent.SELECTED));
        importNewVulnsCheckbox.setSelected(extensionSettings.importNewVulns());

        JButton importCurrentVulnsButton = new JButton("Import current vulnerabilities");
        importCurrentVulnsButton.addActionListener(actionEvent -> onImportCurrentVulns(inScopeCheckbox.isSelected(), importCurrentVulnsButton));

        JButton refreshWorkspaces = new JButton("Refresh active workspace's list");
        refreshWorkspaces.addActionListener(actionEvent -> loadWorkspaces());

        JLabel workspaceLabel = new JLabel("Active workspace:");
        workspaceCombo = new JComboBox<>();
        workspaceCombo.setEnabled(false);

        workspaceCombo.addActionListener(actionEvent -> onWorkspaceSelected((Workspace) workspaceCombo.getSelectedItem()));


        GroupLayout layout = new GroupLayout(settingsPannel);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        settingsPannel.setLayout(layout);

        layout.setHorizontalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(importNewVulnsCheckbox)
                        .addComponent(inScopeCheckbox)
                        .addComponent(importCurrentVulnsButton)
                        .addComponent(refreshWorkspaces)
                )
                .addGroup(layout.createParallelGroup()
                        .addComponent(componentsSeparator)
                )
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(workspaceLabel)
                        .addComponent(workspaceCombo)
                )
        );

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(importNewVulnsCheckbox)
                        .addComponent(workspaceLabel)
                        .addComponent(componentsSeparator)
                )

                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addComponent(inScopeCheckbox)
                        .addComponent(workspaceCombo, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                )
                .addComponent(importCurrentVulnsButton)
                .addComponent(refreshWorkspaces)

        );
        layout.linkSize(SwingConstants.VERTICAL, workspaceLabel, componentsSeparator);

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

    private Component setupNewWorkspacePanel() {
        JPanel newWorkspacePanet = new JPanel();
        newWorkspacePanet.setBorder(BorderFactory.createTitledBorder("New Workspace"));

        JLabel newWorkspaceLabel = new JLabel("Name: ");
        newWorkspaceText = new JTextField();
        JButton createNewWorkspaceButton = new JButton("Create");
        createNewWorkspaceButton.addActionListener(actionEvent -> createWorkspace());

        GroupLayout layout = new GroupLayout(newWorkspacePanet);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        newWorkspacePanet.setLayout(layout);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(newWorkspaceLabel)
                        )
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(newWorkspaceText, 256, 256, 256)
                        )
                        .addComponent(createNewWorkspaceButton)

        );

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                .addComponent(newWorkspaceLabel)
                                .addComponent(newWorkspaceText)
                                .addComponent(createNewWorkspaceButton)
                        )
        );

        layout.linkSize(SwingConstants.VERTICAL, newWorkspaceText);
        layout.linkSize(SwingConstants.HORIZONTAL, newWorkspaceText);


        return newWorkspacePanet;
    }

    private Component setupStatusPanel() {
        JPanel statusPanet = new JPanel();
        statusPanet.setBorder(BorderFactory.createTitledBorder("Status"));

        statusLabel = new JLabel("...");

        GroupLayout layout = new GroupLayout(statusPanet);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        statusPanet.setLayout(layout);

        layout.setHorizontalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                        .addComponent(statusLabel)
                )
        );

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addComponent(statusLabel)
        );


        return statusPanet;
    }

    private Component setupMessagesPanel() {
        JPanel messagesPanel = new JPanel();
        messagesPanel.setBorder(BorderFactory.createTitledBorder("Messages"));
        messagesTextArea = new JTextArea();

        messagesTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(messagesTextArea);
        JButton clearButton = new JButton("Clear messages");
        clearButton.addActionListener(actionEvent -> messagesTextArea.setText(null));

        GroupLayout layout = new GroupLayout(messagesPanel);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        messagesPanel.setLayout(layout);

        layout.setHorizontalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                        .addComponent(scrollPane, 500, 500, 500)
                        .addComponent(clearButton)
                )
        );

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addComponent(scrollPane, 486, 486, 486)
                .addComponent(clearButton)
        );


        return messagesPanel;
    }

    /**
     * State machine that depending on the status of the extension, will call the apropriate method.
     */
    private void onStatusPressed() {
        switch (this.status) {
            case DISCONNECTED:
                connect();
                break;
            case CONNECTED:
                login();
                break;
            case NEEDS_2FA:
                verifyToken();
                break;
            case LOGGED_IN:
                logout();
                break;
        }
    }

    /**
     * Performs a login using the information filled in the fields.
     */
    private void login() {
        String username = usernameText.getText().trim();

        if (username.isEmpty()) {
            showErrorAlert("Username is empty.");
            return;
        }

        String password = new String(passwordField.getPassword()).trim();

        if (password.isEmpty()) {
            showErrorAlert("Password is empty.");
            return;
        }

        try {
            faradayConnector.login(username, password);
        } catch (InvalidCredentialsException e) {

            showErrorAlert("Invalid credentials.");
            passwordField.setText("");
            setLoginStatus("Invalid credentials");
            return;

        } catch (SecondFactorRequiredException e) {

            secondFactorField.setEnabled(true);
            setLoginStatus("2FA Token required");
            statusButton.setText("Verify Token");

            usernameText.setEditable(false);
            passwordField.setEditable(false);
            extensionSettings.setUsername(username);
            secondFactorField.setEditable(true);

            JOptionPane.showMessageDialog(tab, "The 2FA token is required", "Error", JOptionPane.INFORMATION_MESSAGE);
            this.status = FaradayConnectorStatus.NEEDS_2FA;
            return;

        } catch (InvalidFaradayServerException e) {

            showErrorAlert("Invalid Faraday server URL.");
            return;

        }

        extensionSettings.setUsername(username);
        notifyLoggedIn(true);

    }

    /**
     * The server requested for a 2FA token.
     */
    private void verifyToken() {
        String token = secondFactorField.getText().trim();

        if (token.isEmpty()) {
            showErrorAlert("Token is empty.");
            return;
        }

        try {
            faradayConnector.verify2FAToken(token);
        } catch (InvalidCredentialsException e) {
            log("Error when validating token");
            showErrorAlert("Invalid token.");
            return;
        } catch (InvalidFaradayServerException e) {
            showErrorAlert("Unable to connect to Faraday.");
        }

        notifyLoggedIn(true);
        secondFactorField.setEditable(false);
    }

    /**
     * Connects tp the Faraday Server to validate the URL
     */
    private void connect() {
        String faradayUrl = faradayUrlText.getText().trim();

        if (faradayUrl.isEmpty()) {
            showErrorAlert("Faraday URL is empty.");
            return;
        }

        faradayConnector.setBaseUrl(faradayUrl, ignoreSSLErrorsCheckbox.isSelected());

        try {
            faradayConnector.validateFaradayURL();
        } catch (InvalidFaradayServerException e) {
            showErrorAlert("Faraday Server URL is not a valid Faraday server.");
            return;
        } catch (ServerTooOldException e) {
            showErrorAlert("Faraday server is too old to be used with this extension. Please upgrade to the latest version.");
            return;
        }

        usernameText.setEnabled(true);
        passwordField.setEnabled(true);
        statusButton.setText("Login");

        faradayUrlText.setEditable(false);
        setLoginStatus("Connected");
        log("Connected");
        this.status = FaradayConnectorStatus.CONNECTED;
    }

    /**
     * Logouts from the Faraday Server and clears any leftover state.
     */
    private void logout() {
        faradayUrlText.setEditable(true);
        usernameText.setEditable(true);
        passwordField.setEditable(true);
        passwordField.setText("");
        extensionSettings.setPassword("");

        secondFactorField.setEnabled(false);
        secondFactorField.setText("");

        setLoginStatus("Not connected");

        statusButton.setText("Connect");
        log("Logout");
        this.status = FaradayConnectorStatus.DISCONNECTED;

        faradayConnector.logout();
        FaradayConnector.clearCookies();


        workspaceCombo.removeAllItems();
        disablePanel(settingsPannel);
    }

    /**
     * Notifies the UI that we have successfully logged in.
     *
     * @param showAlert Whether to show an alert or not.
     */
    public void notifyLoggedIn(final boolean showAlert) {
        log("Logged in");
        if (showAlert) {
            setStatus("Logged in");
            JOptionPane.showMessageDialog(tab, "Login successful!", "Logged in", JOptionPane.INFORMATION_MESSAGE);
        }
        faradayUrlText.setEditable(false);
        usernameText.setEditable(false);
        passwordField.setEditable(false);
        statusButton.setText("Logout");
        setLoginStatus("Logged in");
        this.status = FaradayConnectorStatus.LOGGED_IN;
        loadWorkspaces();
        enablePanel(settingsPannel);

        extensionSettings.setUsername(usernameText.getText());
        extensionSettings.setPassword(new String(passwordField.getPassword()).trim());
        extensionSettings.setFaradayURL(faradayUrlText.getText());
    }

    /**
     * Notifies the UI that a 2FA token is needed.
     */
    public void notify2FATokenNeeded() {
        usernameText.setEnabled(true);
        passwordField.setEnabled(true);

        faradayUrlText.setEditable(false);
        usernameText.setEditable(false);
        passwordField.setEditable(false);

        secondFactorField.setEnabled(true);
        secondFactorField.setEditable(true);

        setLoginStatus("2FA Token required");
        statusButton.setText("Verify Token");
        log("Verify Token");
        this.status = FaradayConnectorStatus.NEEDS_2FA;
    }

    /**
     * Restores the default settings.
     */
    private void restoreSettings() {
        logout();
        extensionSettings.restore();
        FaradayConnector.clearCookies();
        faradayUrlText.setText(extensionSettings.getDefaultFaradayUrl());
    }

    /**
     * Loads the available workspaces from the Faraday Server and populates the combo box.
     */
    private void loadWorkspaces() {
        String currentWorkspaceName = extensionSettings.getCurrentWorkspace();

        workspaceCombo.removeAllItems();

        try {
            List<Workspace> workspaceList = faradayConnector.getWorkspaces();
            workspaceList.stream().filter(ws -> ws.isActive() == true).forEach(workspaceCombo::addItem);

            if (!currentWorkspaceName.isEmpty()) {
                workspaceList.stream()
                        .filter(workspace -> workspace.getName().equals(currentWorkspaceName))
                        .findFirst()
                        .ifPresent(workspace -> workspaceCombo.setSelectedItem(workspace));
            }


        } catch (CookieExpiredException | InvalidFaradayServerException e) {
            log("Could not fetch workspaces: " + e);
        }
    }

    /**
     * Create a new workspace
     @param workspace The name of the new workspace.
     */
    private void createWorkspace() {
        String workspaceName = newWorkspaceText.getText().trim();
        newWorkspaceText.setText("");
        try {
            Workspace newWorkspace = faradayConnector.createWorkspace(workspaceName);
            extensionSettings.setCurrentWorkspace(workspaceName);
            loadWorkspaces();
            log("New workspace created: " + workspaceName);
        } catch (InvalidFaradayServerException e) {
            log("Could not create workspace: " + e);
        }catch (ObjectNotCreatedException e) {
            log("Unable to create object workspace: " + e);
            return;
        }
    }

    /**
     * Callback for when a workspace is selected on the extension settings
     *
     * @param workspace The workspace that was selected.
     */
    private void onWorkspaceSelected(Workspace workspace) {
        if (workspace == null) {
            return;
        }
        faradayConnector.setCurrentWorkspace(workspace);
        extensionSettings.setCurrentWorkspace(workspace.getName());
    }

    /**
     * Callback for when the user wants to import all the vulnerabilities.
     *
     * @param onlyInScope Only import vulnerabilities in the burp scope
     */
    private void onImportCurrentVulns(boolean onlyInScope, JButton button) {
        runInThread(() -> {
            int vuln_count;
            int created_vulns = 0;
            try {

                button.setEnabled(false);
                IScanIssue[] scanIssuesArray = null;
                scanIssuesArray = callbacks.getScanIssues(null);
                if (scanIssuesArray == null){
                        showErrorAlert("This option is only available for Burp Pro.");
                        return ;
                }

                List<IScanIssue> issues = Arrays.asList(scanIssuesArray);
                if (onlyInScope) {
                    issues = issues.stream().filter(issue -> callbacks.isInScope(issue.getUrl())).collect(Collectors.toList());
                }

                final List<Vulnerability> vulnerabilities = issues.stream().map(VulnerabilityMapper::fromIssue).collect(Collectors.toList());
                final Workspace workspace = faradayConnector.getCurrentWorkspace();
                vuln_count = issues.size();
                String message = "Sending " + vuln_count + " vulnerabilities";
                log(message);
                setStatus(message);
                int commandId;
                if (!commandsMap.containsKey(workspace.getId())){
                    Command command = new Command();
                    command.setCommand("Vulns from issues");
                    commandId = addCommand(command, workspace);
                    commandsMap.put(workspace.getId(), commandId);
                }
                else {
                    commandId = commandsMap.get(workspace.getId());
                }
                if (issues.size() > 0){

                    for (Vulnerability vulnerability : vulnerabilities) {
                        vulnerability.setCommandId(commandId);
                        if (addVulnerability(vulnerability, workspace)) {
                            log("Created Vulnerability");
                            created_vulns ++;
                        }
                    }
                    message = "Created " + created_vulns + " of " + vuln_count + " vulnerabilities";
                    setStatus(message);
                    showInfoAlert(message);
                }else{
                    message = "No vulnerabilities found.";
                    showInfoAlert(message);
                    setStatus(message);
                }

            } catch (Exception e) {
                showInfoAlert("Error: " + e);
                log("Error: " + e);
            }
            button.setEnabled(true);

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

    private void setLoginStatus(final String status) {
        loginStatusLabel.setText(status);
        setStatus(status);
    }

    public void setStatus(final String status) {
        statusLabel.setText(status);
    }

    private void log(final String msg) {
        this.stdout.println("[UI] " + msg);
        addMessage(msg);
    }

    public void addMessage(final String message){
        Date date = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        messagesTextArea.append("[" + formatter.format(date) + "] " + message + "\n");
    }
    /**
     * Disables a panel and all its subcomponents.
     *
     * @param panel The panel to disable.
     */
    private void disablePanel(Component panel) {
        Arrays.stream(((Container) panel).getComponents()).forEach(component -> component.setEnabled(false));
        panel.setEnabled(false);
    }

    /**
     * Enables a panel and all its subcomponents.
     *
     * @param panel The panel to enable.
     */
    private void enablePanel(Component panel) {
        Arrays.stream(((Container) panel).getComponents()).forEach(component -> component.setEnabled(true));
        panel.setEnabled(true);
    }

    public void showErrorAlert(final String message) {
        showAlert(message, JOptionPane.ERROR_MESSAGE);
    }

    public void showInfoAlert(final String message) {
        showAlert(message, JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Shows an alert in a thread safe manner.
     *
     * @param message The message to show.
     * @param type    The alert type.
     */
    private void showAlert(final String message, final int type) {
        log(message);
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(tab, message, "Info", type));
    }

    public int addCommand(final Command command, final Workspace workspace) {
        int commandId;
        try {
             commandId = faradayConnector.addCommandToWorkspace(command, workspace);
        } catch (ObjectNotCreatedException e) {
            log("Unable to create object tree: " + e);
            return 0;
        } catch (InvalidFaradayServerException e) {
            showErrorAlert("Could not connect to Faraday Server. Please check that it is running and that you are authenticated.");
            return 0;
        } catch (Exception e) {
            log("Add Command Error: " + e);
            return 0;
        }

        return commandId;
    }

    public boolean addVulnerability(final Vulnerability vulnerability, final Workspace workspace) {

        try {
            faradayConnector.addVulnerabilityToWorkspace(vulnerability, workspace);
        } catch (ObjectNotCreatedException e) {
            log("Unable to create object tree: " + e);
            return false;
        } catch (InvalidFaradayServerException e) {
            showErrorAlert("Could not connect to Faraday Server. Please check that it is running and that you are authenticated.");
            return false;
        } catch (Exception e) {
            log("Add Vuln Error: " + e);
            return false;
        }

        return true;
    }

    /**
     * Helper to run a runnable functions in a separated thread.
     * Used to call Faraday apis and get a result from them.
     * @param runnable The runnable to run.
     */
    public static void runInThread(final Runnable runnable) {
        new SwingWorker<Void, Void>() {

            @Override
            protected Void doInBackground() {
                runnable.run();

                return null;
            }
        }.execute();
    }

}
