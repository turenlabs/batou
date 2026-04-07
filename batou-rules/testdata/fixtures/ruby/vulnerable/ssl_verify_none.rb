# GTSS-RB-008: Insecure SSL configuration

require 'net/http'
require 'openssl'

def insecure_request(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # Vulnerable: SSL verification disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  response = http.get(uri.path)
  response.body
end

def insecure_rest_client
  # Vulnerable: peer verification disabled
  RestClient::Resource.new(
    "https://api.example.com",
    verify_peer: false
  )
end
