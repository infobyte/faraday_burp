![Java CI with Gradle](https://github.com/infobyte/faraday_burp/workflows/Java%20CI%20with%20Gradle/badge.svg?branch=master)
# Faraday Extension for Burp

Share the results of your application security work in Faraday https://faradaysec.com

This extension will allow you to import requests and issues from your Burp Suite
into a Faraday workspace.


## Download  
You can get the precompiled extension over here:
[Download](https://github.com/infobyte/faraday_burp/releases/latest)

## Documentation
[Official Burp Extension Documentation](https://support.faradaysec.com/portal/kb/articles/https-support-faradaysec-com-portal-kb-articles-burp-plugin)

## Compatibility
This extension is supported in Burp's Community & Pro editions

## Building

In the root of the project, run:

    $ ./gradlew fatJar
    
This will download the necessary dependencies and build a fat `.jar` that is ready to be loaded in Burp.

You can find the file built under `build/libs/`

