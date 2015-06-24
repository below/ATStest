# ATStest
A script to check what needs to be done for talk to a host in iOS 9. 

__It currently requires `nmap` to live in `/usr/local/bin`__

This is work in progress, you are more than welcome to contribute!

The idea of this script is to check the requirements for App Transport Security in iOS 9, as outlined in the [App Transport Security Technote](https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/index.html#//apple_ref/doc/uid/TP40016240-CH1-SW3 "App Transport Security Technote") 

The requrements are:

1.	TLS requires at least version 1.2.
2.	Connection ciphers are limited to those that provide forward secrecy (see below for the list of ciphers.)
3.	The service requires a certificate using at least a SHA256 fingerprint with either a 2048 bit or greater RSA key, or a 256bit or greater Elliptic-Curve (ECC) key.
4.	Invalid certificates result in a hard failure and no connection.

Currently, the script only tests for the ciphers (item 2). If you add checks for the other requirements, and hint of "what to do" is a nice touch

Alexander von Below, Alex@vonBelow.Com 2015