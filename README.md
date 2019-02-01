# Faraday Extension for Burp

This extension will allow you to import requests and issues from your Burp 
workspace into Faraday.

## Building

In the root of the project, run:

    $ ./gradlew fatJar
    
This will download the necessary dependencies and build a fat `.jar` that is ready to be loaded in Burp.

You can find the file built under `build/libs/`
