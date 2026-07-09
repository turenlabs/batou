class ConfigController < ApplicationController
  ALLOWED_CONFIGS = %w[database redis cache].freeze
  def show
    name = params[:config]
    return head(:bad_request) unless ALLOWED_CONFIGS.include?(name)
    data = File.read(Rails.root.join("config", "#{name}.yml"))
    render plain: data
  end
end
