# Safe: Proper SSL verification

require 'net/http'
require 'openssl'

def secure_request(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  # Safe: SSL verification enabled (default)
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  response = http.get(uri.path)
  response.body
end

def secure_rest_client
  # Safe: peer verification enabled
  RestClient::Resource.new(
    "https://api.example.com",
    verify_peer: true
  )
end
