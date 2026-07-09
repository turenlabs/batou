class LinksController < ApplicationController
  ALLOWED_HOSTS = %w[example.com www.example.com].freeze
  def go
    url = params[:url]
    uri = URI.parse(url)
    return redirect_to root_path unless ALLOWED_HOSTS.include?(uri.host)
    redirect_to url
  end
end
