# Faraday Extension for Burp

This extension will allow you to import requests and issues from your Burp 
workspace into Faraday.

### Installation
#### Burp PRO users

You can find Faraday in the Burp App Store!

Go to `Extender-> BApp Store`, and then install the Faraday extension. 
Then make sure the extension is loaded in the Extensions tab.

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/burp/store.png)

#### Burp Free users

Get the latest version of the extension `.jar` by heading to 
the [GitHub Repository](https://github.com/infobyte/faraday_burp/releases/latest) and download
the file named `faraday-burp-v2.x.jar`

Go to `Extender-> Extensions` and click in the Add button.

In the Extension Details section, leave the extension type as Java, and the extension file
should be the path to the `faraday-burp-v2.x.jar` file you just downloaded.
Click Next, and if everything went well, you should see no errors and you can close the window.
Then make sure the extension is loaded in the Extensions tab.

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/burp/add_extension.png)

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/burp/loaded.png)

### Configuration options

Once the Faraday extension is loaded into your Burp, you will see a new tab called `Faraday`.

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/burp/configuration.png)

The first step you should complete upon installation is logging in to you Faraday instance.

For this, complete the Faraday Server URL with the address where your server is running. If it is the same machine,
you can leave it as it is.

Once you are sure the URL is correct, click the `Connect` button so that the extension can validate your server.

If all goes okay, the username and password fields will be enabled for you to fill them in, and click `Login`.
If a 2FA token is requested by the server, you will be asked to provide it so that we can authenticate.

Once authenticated, you will be able to:

1) Import the vulnerabilities you've found so far.

3) Choose whether the vulnerabilities should be imported automatically as soon as they are found or not (it's disabled by default).

4) Restore the Faraday extension's configuration.

### Send to Faraday

Also, we've added the possibility to send the issues and requests to Faraday with a new option in the context menu

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/burp/send_to.png)
