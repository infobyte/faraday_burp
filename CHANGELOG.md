# v2.9.1 - 2025/02/20

* [FIX] Updated workspace listing for compatibility with Faraday API. The minimum required Faraday version is now 5.1.0. #25
* [FIX] Addressed an issue with the vulnerability import functionality. #26


# v2.9 - 2022/12/15

* Add create workspace button

# v2.8 - 2022/09/19

* Add refresh workspace button
* Fix website field
* Now the host,services and vulns create have a command associated

# v2.7 - 2021/07/21

* Use Faraday api version 3

# v2.6 - 2021/03/26

* Don't show inactive workspaces
* Send "Detail" field to "Data" field in faraday

# v2.0 - 2019/02/01

* Rewrote the extension using Java.
* Added support for 2FA login.
* Use the Faraday Server REST API instead of the client RPC API
* Remove the requirement to keep the Faraday Client running