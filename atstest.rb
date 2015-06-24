# Alex@vonBelow.Com 2015
# This is work in progress, you are more than welcome to contribute!

###########
# WARNING #
###########

# Currently this script has some heavy dependencies, which may cause it to be useless. Among these are the assumption, that your nmap
# is linked against a version of openssl that supports TLS 1.2, and that it is in a specific location
# We are trying to remove these dependencies

# The idea of this script is to check the requirements for App Transport Security in iOS 9, as outlined here: https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/index.html#//apple_ref/doc/uid/TP40016240-CH1-SW3

# The requrements are:
# * TLS requires at least version 1.2.
# * Connection ciphers are limited to those that provide forward secrecy (see below for the list of ciphers.)
# * The service requires a certificate using at least a SHA256 fingerprint with either a 2048 bit or greater RSA key, or a 256bit or greater Elliptic-Curve (ECC) key.
# * Invalid certificates result in a hard failure and no connection.

# Currently, the script only tests for the ciphers. If you add checks for the other requirements, and hint of "what to do" is a nice touch

host = ARGV[0]

if host == nil || host == ""
  puts "Please provide a hostname as argument, e.g. example.com"
  exit 1
end

nmappath = "/usr/local/bin/nmap"

puts "Getting server info for #{host}"

content = `#{nmappath} --script ssl-cert,ssl-enum-ciphers -p 443 #{host}`

if $? == 0

  if content =~ /(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384|TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA|TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256|TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384|TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256|TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)/
    puts "Ciphers OK!"
  else
    if content =~/(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384|TLS_DHE_RSA_WITH_AES_128_GCM_SHA256|TLS_DHE_RSA_WITH_AES_256_CBC_SHA256|TLS_DHE_RSA_WITH_AES_256_CBC_SHA|TLS_DHE_RSA_WITH_AES_128_CBC_SHA256|TLS_DHE_RSA_WITH_AES_128_CBC_SHA|TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_128_GCM_SHA256|TLS_RSA_WITH_AES_256_CBC_SHA256|TLS_RSA_WITH_AES_256_CBC_SHA|TLS_RSA_WITH_AES_128_CBC_SHA256|TLS_RSA_WITH_AES_128_CBC_SHA)/
      
      puts "You need to ENABLE forward secrecy on #{host}. Not only will it make your connection safer, you will also benefit from more speed and lower latencies."
      puts "If you have no control over the configuration of #{host}, you can set NSExceptionRequiresForwardSecrecy to NO"
      puts "Bear in mind Apple can deprecate or disable this exception at any time. Updating your server is preferred"
    end
    puts "You need to update #{host}. Seriously"
  end

else
  puts "Unable to nmap host"
  exit 1
end