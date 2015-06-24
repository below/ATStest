# ATStest
A script to check what needs to be done for talking to a host in iOS 9. 

## WARNING 

Currently this script has some heavy dependencies, which may cause it to be useless. Among these are the assumption, that your `nmap` is linked against a version of openssl that supports TLS 1.2.
Also, OpenSSL CLI tools need to be available.

We are trying to remove these dependencies

This is work in progress, you are more than welcome to contribute!

The idea of this script is to check the requirements for App Transport Security in iOS 9, as outlined in the [App Transport Security Technote](https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/index.html#//apple_ref/doc/uid/TP40016240-CH1-SW3 "App Transport Security Technote") 

The requirements are:

1.	TLS requires at least version 1.2.
2.	Connection ciphers are limited to those that provide forward secrecy (see below for the list of ciphers.)
3.	The service requires a certificate using at least a SHA256 fingerprint with either a 2048 bit or greater RSA key, or a 256bit or greater Elliptic-Curve (ECC) key.
4.	Invalid certificates result in a hard failure and no connection.

Currently, the script tests for the ciphers (item 2) and the certificate fields in item 3.

If you add checks for the other requirements, and hint of "what to do" is a nice touch


## Usage
```
$ ruby atstest.rb --help
Usage: atstest hostname [OPTIONS]

Options
    -p, --port PORT                  TCP port. Default 443
    -s, --openssl PATH               Full path to the OpenSSL binary.
    -n, --nmap PATH                  Full path to the nmap binary.
    -v, --verbose                    Display more stuff.
    -q, --quiet                      Suppress all output. Overrides verbose output!

Common options:
    -h, --help                       Show this message
```

## Sample outputs
```
$ ruby atstest.rb -v api.facebook.com
Fetching certificate from api.facebook.com:443... done.
Parsing certificate... done.
Checking ciphers for api.facebook.com:443... Ciphers OK!
Checking Key and Algorithm... RSA Public Key with 2048 bits OK!
Checking Signature Algorithm... Signature hash sha1WithRSAEncryption too short.
```

```
$ ruby atstest.rb -v api.centerdevice.de
Fetching certificate from api.centerdevice.de:443... done.
Parsing certificate... done.
Checking ciphers for api.centerdevice.de:443... Ciphers OK!
Checking Key and Algorithm... RSA Public Key with 2048 bits OK!
Checking Signature Algorithm... Signature algorithm sha256WithRSAEncryption OK!
```

Alexander von Below, Alex@vonBelow.Com 2015
