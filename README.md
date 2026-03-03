![Java CI with Gradle](https://github.com/infobyte/faraday_burp/workflows/Java%20CI%20with%20Gradle/badge.svg?branch=master)

# Faraday Extension for Burp Suite

Import Burp Suite scan results, issues, and HTTP requests directly into [Faraday](https://faradaysec.com) — the collaborative penetration testing and vulnerability management platform.

## Overview

The Faraday Burp extension bridges Burp Suite and Faraday Server, allowing you to:

- **Import scan issues** — Push Burp Scanner findings (Pro edition) into a Faraday workspace as categorized vulnerabilities with full request/response data.
- **Send individual requests** — Right-click any request in Proxy History, Intruder, Repeater, or Site Map and send it to Faraday.
- **Auto-import** — Optionally have new scanner findings imported automatically as they are discovered.
- **Create workspaces** — Create new Faraday workspaces directly from the extension UI.

## Requirements

| Component | Minimum Version |
|-----------|----------------|
| Faraday Server | **5.1.0** |
| Burp Suite | Community or Professional edition |
| Java | 8+ (JRE already bundled with Burp) |

## Installation

### Option A: Download the Pre-built JAR (Recommended)

1. Go to the [GitHub Releases](https://github.com/infobyte/faraday_burp/releases/latest) page.
2. Download the file named `faraday-burp-v2.x.jar` (the "fat JAR" with all dependencies bundled).
3. In Burp Suite, navigate to **Extensions → Extensions** (Burp 2024+) or **Extender → Extensions** (older versions).
4. Click **Add**.
5. Set **Extension type** to **Java**.
6. For **Extension file**, browse to the downloaded `.jar` file.
7. Click **Next**. If everything loads correctly you will see no errors in the output tab.
8. Verify the extension appears in the Extensions list with a check mark.

### Option B: Build from Source

Clone the repository and build using Gradle:

```shell
git clone https://github.com/infobyte/faraday_burp.git
cd faraday_burp
./gradlew fatJar
```

The compiled JAR is written to `build/libs/faraday-burp-v2.x.jar`. Load it into Burp using the same steps as Option A.

**Building with Docker** (no local JDK required):

```shell
docker run --rm -it -v "$(pwd)":/src -w /src openjdk:9-jdk ./gradlew fatJar
```

## Configuration

Once the extension is loaded, a new **Faraday** tab appears in Burp's main tab bar.

### 1. Connect to Faraday Server

| Field | Description |
|-------|-------------|
| **Faraday Server URL** | Full URL of your Faraday instance (default: `http://127.0.0.1:5985`). |
| **Ignore SSL Errors** | Check this box if your Faraday server uses a self-signed or untrusted TLS certificate. |

Click **Connect** to validate the server. The status will change to "Connected" on success.

### 2. Authenticate

After connecting, the **Username** and **Password** fields become active.

1. Enter your Faraday credentials and click **Login**.
2. If your account has **two-factor authentication (2FA)** enabled, you will be prompted for your TOTP token. Enter it and click **Verify Token**.
3. On success the status shows "Logged in" and the Extension Settings panel becomes active.

> **Note:** Credentials are stored in Burp's extension settings so you are automatically logged in next time Burp starts (unless you click Restore Settings).

### 3. Select a Workspace

From the **Active workspace** dropdown, choose the Faraday workspace where vulnerabilities should be created. Only active workspaces are shown; click **Refresh active workspace's list** to reload.

You can also **create a new workspace** directly from the New Workspace panel at the bottom of the Faraday tab.

## Usage

### Import All Current Scanner Issues (Burp Pro)

1. In the Extension Settings section, click **Import current vulnerabilities**.
2. Optionally check **Only in Burp scope** to limit the import to targets in your Burp scope.
3. The extension maps each Burp issue to a Faraday vulnerability, creating the corresponding host, service, and vulnerability objects via the Faraday API.
4. A summary message reports how many vulnerabilities were created.

### Auto-Import New Issues (Burp Pro)

Check **Auto import new vulnerabilities** in the Extension Settings. Every new finding reported by the Burp Scanner will be pushed to Faraday automatically in the selected workspace.

### Send via Context Menu

Right-click in any of these Burp views to see the Faraday context menu option:

| Burp View | Menu Item |
|-----------|-----------|
| Scanner Results | **Send issue to Faraday** |
| Proxy History | **Send request to Faraday** |
| Site Map | **Send request to Faraday** |
| Intruder Results | **Send request to Faraday** |
| Search Results | **Send request to Faraday** |

When sending an issue, the full vulnerability details (severity, description, remediation, request, and response) are mapped. When sending a request, it is created as an informational-severity web vulnerability with the full HTTP request/response attached.

### Severity Mapping

The extension translates Burp severity levels to Faraday severity levels:

| Burp Severity | Faraday Severity |
|---------------|-----------------|
| High | high |
| Medium | medium |
| Low | low |
| Information | informational |
| False positive | unclassified |

## SSL / Self-Signed Certificate Handling

If your Faraday server uses HTTPS with a self-signed certificate:

1. Check the **Ignore SSL Errors** checkbox **before** clicking Connect.
2. The extension will accept any server certificate for the configured host, bypassing Java's default trust store validation.

> **Security note:** Only enable this option when connecting to a trusted server on a trusted network, as it disables certificate verification for the Faraday connection.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Could not connect to Faraday" | Verify the URL is correct and the Faraday server is running. Check that the port (default 5985) is reachable. |
| "Faraday server is too old" | Upgrade Faraday Server to version **5.1.0** or later. |
| "Invalid credentials" | Double-check your username and password. Re-enter if necessary. |
| 2FA prompt keeps appearing | Ensure your authenticator app clock is synced. Enter the token promptly. |
| "Import current vulnerabilities" button does nothing | This feature requires **Burp Suite Professional**. The Community edition does not expose scanner issues to extensions. |
| Extension does not load | Ensure the extension type is set to **Java** (not Python or Ruby). Verify Java version compatibility. |
| Workspaces dropdown is empty | Click **Refresh active workspace's list**. Only active workspaces are shown. |
| Connection issues behind a proxy | Configure your JVM/Burp proxy settings. The extension uses Burp's HTTP stack for outbound requests. |

### Restore Defaults

Click **Restore Settings** in the Other Settings panel to clear all saved credentials, reset the server URL to `http://127.0.0.1:5985`, and disconnect from the current session.

## How It Works

The extension communicates with Faraday Server via its REST API (v3):

1. **Authentication** — `POST /_api/login` (with optional 2FA via `POST /_api/confirmation`).
2. **Workspace listing** — `GET /_api/v3/ws` to retrieve available workspaces.
3. **Data creation** — For each vulnerability, the extension creates a command, host, service, and vulnerability object in the selected workspace using `POST /_api/v3/ws/{workspace}/commands|hosts|services|vulns`.

Duplicate hosts and services are handled gracefully via conflict detection (HTTP 409); duplicate vulnerabilities are skipped.

## Links

- [Faraday Platform](https://faradaysec.com)
- [Faraday Documentation](https://docs.faradaysec.com)
- [GitHub Repository](https://github.com/infobyte/faraday_burp)
- [Report an Issue](https://github.com/infobyte/faraday_burp/issues)

## License

This project is licensed under the GPL-3.0 License. See [LICENSE](LICENSE) for details.
