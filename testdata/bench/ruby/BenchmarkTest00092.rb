require 'net/http'
class HealthController < ApplicationController
  INTERNAL_SERVICES = %w[db cache queue].freeze
  def check
    service = params[:service]
    return head(:bad_request) unless INTERNAL_SERVICES.include?(service)
    uri = URI.parse("http://localhost:9090/health/#{service}")
    response = Net::HTTP.get(uri)
    render json: { status: "ok" }
  end
end
