require 'net/http'
class WebhookController < ApplicationController
  ALLOWED_HOSTS = %w[api.example.com hooks.example.com].freeze
  def fetch
    url = params[:url]
    uri = URI.parse(url)
    return head(:forbidden) unless ALLOWED_HOSTS.include?(uri.host)
    response = Net::HTTP.get(uri)
    render plain: response
  end
end
