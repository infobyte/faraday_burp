# Faraday Extension for Burp Suite — Step-by-Step Guide

This guide walks you through installing, configuring, and using the Faraday Burp extension to import your application security findings into Faraday.

---

## Prerequisites

Before you begin, make sure you have:

- **Faraday Server** version **5.1.0** or later, running and accessible over the network.
- **Burp Suite** Community or Professional edition installed.
- A valid Faraday user account with access to at least one workspace.

---

## Step 1: Download the Extension

1. Open your browser and navigate to the [latest release](https://github.com/infobyte/faraday_burp/releases/latest) on GitHub.
2. Under **Assets**, download the file named `faraday-burp-v2.x.jar`. This is a fat JAR that includes all required dependencies — no additional libraries are needed.
3. Save the file to a location you can easily find (e.g., `~/burp-extensions/`).

> **Alternative — build from source:**
> ```shell
> git clone https://github.com/infobyte/faraday_burp.git
> cd faraday_burp
> ./gradlew fatJar
> ```
> The built JAR will be at `build/libs/faraday-burp-v2.x.jar`.

---

## Step 2: Install the Extension in Burp Suite

1. Launch **Burp Suite**.
2. Go to the **Extensions** tab (in newer Burp versions) or **Extender → Extensions** (in older versions).

   ```
   ┌──────────────────────────────────────────────────────┐
   │  Burp Suite                                          │
   │  ┌────────┬───────────┬───────────┬─────────────┐    │
   │  │ Target │  Proxy    │ Intruder  │ Extensions  │    │
   │  └────────┴───────────┴───────────┴─────────────┘    │
   └──────────────────────────────────────────────────────┘
   ```

3. Click the **Add** button.
4. In the dialog that appears:
   - **Extension type:** Select **Java**.
   - **Extension file (.jar):** Click **Select file...** and browse to the `faraday-burp-v2.x.jar` you downloaded.

   ```
   ┌─ Extension Details ───────────────────────────────┐
   │                                                    │
   │  Extension type:    [Java           ▼]             │
   │                                                    │
   │  Extension file:    /path/to/faraday-burp-v2.x.jar│
   │                     [Select file...]               │
   │                                                    │
   │                            [Next]    [Cancel]      │
   └────────────────────────────────────────────────────┘
   ```

5. Click **Next**.
6. If everything loads successfully, the output pane will show no errors. Click **Close**.
7. Verify the extension is listed and has a check mark in the **Loaded** column.

   ```
   ┌─ Extensions ──────────────────────────────────────────────────┐
   │  ☑  Faraday plugin for Burp (v: 2.9.1)    Java    Loaded     │
   └───────────────────────────────────────────────────────────────┘
   ```

---

## Step 3: Connect to Faraday Server

1. Click the new **Faraday** tab that appeared in Burp's main tab bar.

   ```
   ┌────────┬───────────┬───────────┬─────────────┬──────────┐
   │ Target │  Proxy    │ Intruder  │ Extensions  │ Faraday  │
   └────────┴───────────┴───────────┴─────────────┴──────────┘
   ```

2. In the **Login to Faraday** panel, you will see:

   ```
   ┌─ Login to Faraday ───────────────────────────────────┐
   │                                                       │
   │  Faraday Server URL:  [http://127.0.0.1:5985      ]  │
   │  Username:            [                            ]  │
   │  Password:            [                            ]  │
   │  2FA Token:           [                            ]  │
   │                       ☐ Ignore SSL Errors             │
   │                                                       │
   │  [Connect]                            Not connected   │
   └───────────────────────────────────────────────────────┘
   ```

3. Enter the **Faraday Server URL**. The default is `http://127.0.0.1:5985`. If your server is on a different host or port, update accordingly (e.g., `https://faraday.example.com:5985`).

4. **If your server uses a self-signed TLS certificate**, check the **Ignore SSL Errors** checkbox now, _before_ clicking Connect. See [SSL / Self-Signed Certificates](#ssl--self-signed-certificates) for details.

5. Click **Connect**.
6. The status should change to **Connected**. If it fails, verify the URL and that the Faraday server is running.

---

## Step 4: Log In

1. Once connected, the **Username** and **Password** fields become active.
2. Enter your Faraday credentials.
3. Click **Login**.

### If 2FA Is Enabled

If your Faraday account has two-factor authentication enabled:

1. After clicking Login, a dialog will appear: _"The 2FA token is required"_.
2. The **2FA Token** field becomes active and the button changes to **Verify Token**.
3. Open your authenticator app (e.g., Google Authenticator, Authy) and enter the current 6-digit code.
4. Click **Verify Token**.

### On Successful Login

The status will change to **Logged in** and a confirmation dialog appears. The Extension Settings panel and workspace selector are now active.

```
┌─ Login to Faraday ───────────────────────────────────┐
│                                                       │
│  Faraday Server URL:  http://127.0.0.1:5985          │
│  Username:            admin                           │
│  Password:            ••••••••                        │
│  2FA Token:                                           │
│                       ☐ Ignore SSL Errors             │
│                                                       │
│  [Logout]                                Logged in    │
└───────────────────────────────────────────────────────┘
```

> **Tip:** Your credentials are persisted in Burp's settings. The next time you launch Burp, the extension will automatically reconnect and log you in.

---

## Step 5: Select a Workspace

1. In the **Extension Settings** panel, look at the **Active workspace** dropdown on the right side.

   ```
   ┌─ Extension Settings ──────────────────────────────────────────┐
   │                                    │                          │
   │  ☐ Auto import new vulnerabilities │  Active workspace:       │
   │  ☐ Only in Burp scope             │  [my-pentest-workspace▼] │
   │  [Import current vulnerabilities]  │                          │
   │  [Refresh active workspace's list] │                          │
   └────────────────────────────────────┴──────────────────────────┘
   ```

2. Select the workspace where you want vulnerabilities to be created.
3. If your workspace is not listed, click **Refresh active workspace's list**.

### Creating a New Workspace

1. In the **New Workspace** panel, enter a name.
2. Click **Create**.
3. The workspace is created on the Faraday server and the dropdown refreshes automatically.

   ```
   ┌─ New Workspace ───────────────────────────────────┐
   │  Name:  [new-project-workspace    ]   [Create]    │
   └───────────────────────────────────────────────────┘
   ```

---

## Step 6: Import Vulnerabilities

You have three ways to send data to Faraday.

### Option A: Bulk Import All Scanner Issues (Burp Pro Only)

1. Click **Import current vulnerabilities** in the Extension Settings panel.
2. Optionally check **Only in Burp scope** to limit the import.
3. Wait for the process to complete. The Messages panel on the right shows progress.
4. A summary dialog reports how many vulnerabilities were created.

   ```
   ┌─ Messages ────────────────────────────────────────┐
   │ [02/03/2026 14:23:01] Sending 47 vulnerabilities  │
   │ [02/03/2026 14:23:02] Created Vulnerability        │
   │ [02/03/2026 14:23:02] Created Vulnerability        │
   │ ...                                                │
   │ [02/03/2026 14:23:15] Created 45 of 47 vulns      │
   └───────────────────────────────────────────────────┘
   ```

### Option B: Enable Auto-Import (Burp Pro Only)

1. Check **Auto import new vulnerabilities**.
2. From this point on, every new finding from the Burp Scanner is automatically sent to the selected Faraday workspace.
3. You can monitor imports in the Messages panel.

### Option C: Right-Click Context Menu (Community & Pro)

1. Navigate to any of these Burp views:
   - **Proxy → HTTP history**
   - **Target → Site map**
   - **Intruder → Attack results**
   - **Scanner → Issue activity** (Pro)
2. Select one or more items.
3. Right-click and choose:
   - **Send issue to Faraday** (from Scanner results)
   - **Send request to Faraday** (from Proxy, Site Map, Intruder, etc.)

   ```
   ┌──────────────────────────────────┐
   │  Copy URL                        │
   │  Add to scope                    │
   │  ──────────────────────────────  │
   │  Send request to Faraday    ◄──── Click this
   │  ──────────────────────────────  │
   │  Send to Repeater                │
   │  Send to Intruder                │
   └──────────────────────────────────┘
   ```

4. The extension creates the host, service, and vulnerability objects in your selected workspace.

---

## Step 7: Verify in Faraday

1. Open the Faraday web UI in your browser.
2. Navigate to the workspace you selected.
3. Check the **Vulnerabilities** view — you should see the imported findings with:
   - Severity mapped from the Burp scale (High/Medium/Low/Information → high/medium/low/informational)
   - Full request and response data attached (for web vulnerabilities)
   - Host and service information auto-created

---

## SSL / Self-Signed Certificates

If your Faraday server uses HTTPS with a self-signed or internally-issued certificate:

1. Before clicking **Connect**, check the **Ignore SSL Errors** checkbox.
2. This tells the extension to accept any certificate presented by the configured Faraday server host.

**Important:** Only use this option when you trust the network and the server. It disables certificate verification for the Faraday connection only — it does not affect Burp's own proxy/scanner traffic.

If you later switch to a properly signed certificate, uncheck the box to restore normal TLS validation.

---

## Restoring Default Settings

If you want to clear all saved settings and start fresh:

1. In the **Other Settings** panel, click **Restore Settings**.
2. This will:
   - Log you out of the current session.
   - Reset the server URL to `http://127.0.0.1:5985`.
   - Clear the saved username and password.
   - Reset auto-import and SSL settings to their defaults.

---

## Troubleshooting

### "Could not connect to Faraday"

- Verify the server URL is correct (include the protocol: `http://` or `https://`).
- Confirm the Faraday server is running: try accessing `http://your-server:5985/_api/config` in a browser.
- Check firewall rules and network connectivity.

### "Faraday server is too old"

- The extension requires Faraday Server **5.1.0** or later.
- Upgrade your Faraday installation following the [official upgrade guide](https://docs.faradaysec.com).

### "Invalid credentials"

- Re-enter your username and password carefully.
- Verify you can log in to the Faraday web UI with the same credentials.
- If using 2FA, ensure your authenticator app is time-synced.

### "Import current vulnerabilities" does nothing or shows an error

- This feature is only available in **Burp Suite Professional**. The Community edition does not expose scanner issues to extensions.
- The right-click **Send request to Faraday** option works in both editions.

### Extension does not appear in Burp

- Ensure you selected **Java** as the extension type (not Python or Ruby).
- Check the Errors tab in the Extensions panel for stack traces.
- Make sure you are using the fat JAR from the releases page, not just the source JAR.

### Workspaces dropdown is empty after login

- Click **Refresh active workspace's list**.
- Only **active** workspaces are displayed. Deactivated workspaces are hidden.

### Messages panel shows errors

- The Messages panel on the right side of the Faraday tab logs all operations. Click **Clear messages** to reset it.
- Common messages like "Vulnerability already exists" indicate a duplicate finding was skipped — this is normal behavior.

---

## Quick Reference

| Action | Where | Steps |
|--------|-------|-------|
| Install extension | Extensions tab | Add → Java → select JAR → Next |
| Connect to server | Faraday tab | Enter URL → Connect |
| Log in | Faraday tab | Enter credentials → Login |
| Select workspace | Extension Settings | Choose from dropdown |
| Bulk import issues | Extension Settings | Click "Import current vulnerabilities" |
| Auto-import | Extension Settings | Check "Auto import new vulnerabilities" |
| Send single item | Any Burp view | Right-click → Send to Faraday |
| Create workspace | New Workspace panel | Enter name → Create |
| Reset everything | Other Settings | Click "Restore Settings" |

---

## Further Reading

- [Faraday Documentation](https://docs.faradaysec.com)
- [Faraday Extension README](README.md)
- [GitHub Repository & Releases](https://github.com/infobyte/faraday_burp)
- [Report a Bug](https://github.com/infobyte/faraday_burp/issues)
