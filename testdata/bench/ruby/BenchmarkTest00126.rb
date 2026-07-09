class OAuthController < ApplicationController
  ALLOWED_PATHS = %w[/dashboard /profile /settings].freeze
  def callback
    next_path = params[:next]
    safe = ALLOWED_PATHS.include?(next_path) ? next_path : "/dashboard"
    redirect_to safe
  end
end
