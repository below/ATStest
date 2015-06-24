# Alex@vonBelow.Com 2015
# This is work in progress, you are more than welcome to contribute!

###########
# WARNING #
###########

# Currently this script has some heavy dependencies, which may cause it to be useless. Among these are the assumption, that your nmap
# is linked against a version of openssl that supports TLS 1.2.
# We are trying to remove these dependencies

# The idea of this script is to check the requirements for App Transport Security in iOS 9, as outlined here: https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/index.html#//apple_ref/doc/uid/TP40016240-CH1-SW3

# The requrements are:
# * TLS requires at least version 1.2.
# * Connection ciphers are limited to those that provide forward secrecy (see below for the list of ciphers.)
# * The service requires a certificate using at least a SHA256 fingerprint with either a 2048 bit or greater RSA key, or a 256bit or greater Elliptic-Curve (ECC) key.
# * Invalid certificates result in a hard failure and no connection.

# Currently, the script only tests for the ciphers, key length and fingerprint algorithm

# If you add checks for the other requirements, and hint of "what to do" is a nice touch

require 'tempfile'
require 'optparse'

# These curve names were taken from https://tools.ietf.org/html/rfc5480
# They have key sizes >= 256 bits. Multiple names in one line signal
# that the same curve was given different names. See the RFC for details.
$acceptable_ecc_curves = [
  'secp256r1', 'prime256v1', 'P-256',
  'sect283k1',
  'sect283r1', 'P-384',
  'secp384r1',
  'sect409k1',
  'sect409r1',
  'secp521r1',
  'sect571k1',
  'sect571r1',
]

# configure defaults
$options = {
  :port    => 443,
  :openssl => "openssl",
  :nmap    => "nmap",
  :verbose => false,
  :quiet   => false,
}

opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: atstest hostname [OPTIONS]"
  opt.separator  ""
  opt.separator  "Options"

  opt.on("-p","--port PORT","TCP port. Default #{$options[:port]}") do |p|
    $options[:port] = p
  end

  opt.on("-s","--openssl PATH", "Full path to the OpenSSL binary.") do |p|
    $options[:openssl] = p
  end

  opt.on("-n", "--nmap PATH", "Full path to the nmap binary.") do |p|
    $options[:nmap] = p
  end

  opt.on("-v", "--verbose", "Display more stuff.") do |p|
    $options[:verbose] = p if not $options[:quiet]
  end

  opt.on("-q", "--quiet", "Suppress all output. Overrides verbose output!") do |p|
    $options[:quiet] = p
    $options[:verbose] = false
  end


  opt.separator ""
  opt.separator "Common options:"

  opt.on_tail("-h", "--help", "Show this message") do
    puts opt
    exit
  end
end

# Helper function to reliably convert strings to numbers if possible
def number_or_nil(string)
  num = string.to_i
  num if num.to_s == string
end

# Fetches the certificate from the server via OpenSSL
# and extracts the leaf certificate information in readable
# text format.
# Returns a string of the PEM data in ASCII / Base64 encoding.
def fetch_leaf_certificate(host, port)
  print "Fetching certificate from #{host}:#{port}... " if $verbose

  # request full certificate chain. contains base64 encoded
  # certificates of the leaf and the chain up to the trusted root.
  content =`echo -n | #{$options[:openssl]} s_client -connect #{host}:#{port} -prexit -showcerts 2>&1`
  if $?.exitstatus != 0
    puts "Error fetching certificate.\n#{content}" if not $quiet
    exit 1
  end

  # cut out the first base64 certificate block. this is the leaf
  # certificate in PEM format.
  leaf_base64=content.match(/(-----BEGIN CERTIFICATE-.*?-END CERTIFICATE-----)/m)[1]

  puts "done." if $verbose
  return leaf_base64
end

# Converts a PEM formatted certificate into readable
# text via OpenSSL.
# Does NOT do any evaluation of the certifcate contents.
# Returns a string of said text representation.
def parse_certificate(cert_base64)
  print "Parsing certificate... " if $verbose
  # write this into a temp file for easier passing to OpenSSL in
  # the next step
  tmp_file = Tempfile.new("atstest-temp")
  tmp_file << cert_base64
  tmp_file.close
 
  tmp_file_path = tmp_file.path

  # decode base64 PEM into readable text
  cert_text=`#{$options[:openssl]} x509 -in #{tmp_file_path} -noout -text -certopt no_sigdump,no_header 2>&1`
  parse_success = $?
  tmp_file.delete
  
  if parse_success.exitstatus != 0
    puts "Problem parsing certificate.\n#{cert_text}" if not $quiet
    exit 1
  end
  puts "done." if $verbose 
  return cert_text
end

# nmaps the server to probe the supported cipher suites.
# checks against Apple's requirements.
# Returns true if ciphers were checked successfully and
# conform to Apple's requirements.
# Returns false in case of problems or if action needs
# to be taken due to unmet requirements.
# Honors the verbose flag to output detailed information
# about the problems encountered.
def check_ciphers(host, port)
  nmappath = $options[:nmap]
  print "Checking ciphers for #{host}:#{port}... " if $verbose

  content = `#{nmappath} --script ssl-cert,ssl-enum-ciphers -p #{port} #{host} 2>&1`

  # Notice: nmap exits with 0 even if the hostname could not be resolved :(
  # This means we need to check for some error cases later ourselves.
  if $?.exitstatus != 0
    puts "Error running nmap!" if not $quiet
    puts "nmap response:\n>>>>>\n#{content}\n<<<<<<<<" if $verbose
    exit 1
  end

  case content

    when /Failed to resolve/
      puts "Failed to resolve hostname #{host}" if not $quiet
      return false

    when /(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384|TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA|TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256|TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384|TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256|TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)/
      puts "Ciphers OK!" if not $quiet

    when /(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384|TLS_DHE_RSA_WITH_AES_128_GCM_SHA256|TLS_DHE_RSA_WITH_AES_256_CBC_SHA256|TLS_DHE_RSA_WITH_AES_256_CBC_SHA|TLS_DHE_RSA_WITH_AES_128_CBC_SHA256|TLS_DHE_RSA_WITH_AES_128_CBC_SHA|TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_128_GCM_SHA256|TLS_RSA_WITH_AES_256_CBC_SHA256|TLS_RSA_WITH_AES_256_CBC_SHA|TLS_RSA_WITH_AES_128_CBC_SHA256|TLS_RSA_WITH_AES_128_CBC_SHA)/
      puts %{
        You need to ENABLE forward secrecy on #{host}. Not only will it make your connection safer,
        you will also benefit from more speed and lower latencies.

        If you have no control over the configuration of #{host}, you can set NSExceptionRequiresForwardSecrecy to NO.
        Bear in mind though that Apple can deprecate or disable this exception at any time.
       
        Updating your server is preferred!"
      } if not $quiet
      return false

    when /\w+_\w+/ # assuming this is some other set of ciphers
      puts "You need to update #{host}. Seriously." if not $quiet
      puts "This is the cipher list we received. It probably dates back to the stone age:\n>>>>>>>>>#{content}<<<<<<<<<" if $verbose

    else
      puts "Could not check ciphers. Unknown response from nmap." if not $quiet
      puts "nmap response:\n>>>>>\n#{content}\n<<<<<<<<" if $verbose
      return false
  end

  return true
end


# Checks the certificate text info passed in as a parameter
# for the public key algorithm and key lengths.
# Returns true if they meet Apple's requirements.
# Returns true if there were problems parsing the input or
# if said requirements were not met.
# Honors the verbose flag for more detailed information about
# what was detected.
def check_key_algo(leaf_text)
  print "Checking Key and Algorithm... " if $verbose

  key_algo = leaf_text.match(/Public Key Algorithm: (.*?)$/m)[1]

  case key_algo
  when "rsaEncryption"
    rsa_keybits=number_or_nil(leaf_text.match(/RSA Public Key: \((\d+) bit\)/m)[1])
    if rsa_keybits < 2048
      puts "RSA Public Key size #{rsa_keybits} < required minimum (2048)" if not $quiet
      return false
    else
      puts "RSA Public Key with #{rsa_keybits} bits OK!" if not $quiet
    end
  
  when /id-ecPublicKey/
    asn1oid=leaf_text.match(/ASN1 OID: (.+?)$/m)[1]
    if not $acceptable_ecc_curves.include?(asn1oid)
      puts "ECC Curve Bits #{asn1oid} not considered strong enough." if not $quiet
      return false
    end
    puts "ECC Key algorithm #{key_algo} with curve #{asn1oid} OK!" if not $quiet

  when /\w+/
    puts "Unknown key algorithm #{key_algo}" if not $quiet
    return false

  else
    puts "Error: Could not determine key algorithm" if not $quiet
    puts "Certificate info: >>>>>>>\n#{leaf_text}\n<<<<<<<<" if $verbose
    return false
  end
  
  return true
end

# Checks the certificate text info passed in as a parameter
# for the fingerprint algorithm and lengths.
# Returns true if they meet Apple's requirements.
# Returns true if there were problems parsing the input or
# if said requirements were not met.
# Honors the verbose flag for more detailed information about
# what was detected.
def check_sig_algo(leaf_text)
  print "Checking Signature Algorithm... " if $verbose

  sig_algo=leaf_text.match(/Signature Algorithm: (.+?)$/m)[1]

  case sig_algo
  when /sha(\d+)WithRSAEncryption/
    sha_sig_bits = number_or_nil $1
    if sha_sig_bits < 256
      puts "Signature hash #{sig_algo} too short." if not $quiet 
      return false
    end

  when /\w+/
    puts "Signature algorithm #{key_algo} considered not strong enough." if not $quiet
    return false

  else
    puts "Error: Could not determine signature algorithm" if not $quiet
    puts "Certificate info: >>>>>>>\n#{leaf_text}\n<<<<<<<<<<" if $verbose
    return false
  end

  puts "Signature algorithm #{sig_algo} OK!" if not $quiet
  return true
end


#####

# parse command line

opt_parser.parse!
host = ARGV[0]
if host == nil || host == ""
  puts opt_parser
  exit 1
end

$verbose = $options[:verbose]
$quiet   = $options[:quiet]
everything_ok = true

cert_base64 = fetch_leaf_certificate(host, $options[:port])
cert_text   = parse_certificate(cert_base64)

everything_ok &= check_ciphers(host, $options[:port])
everything_ok &= check_key_algo(cert_text)
everything_ok &= check_sig_algo(cert_text)

exit everything_ok ? 0 : 1 
