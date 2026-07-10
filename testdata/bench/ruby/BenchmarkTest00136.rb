class ShareController < ApplicationController
  def redirect
    target = params[:target_url]
    uri = URI.parse(target) rescue nil
    return redirect_to root_path unless uri && uri.host == "example.com"
    redirect_to target
  end
end
