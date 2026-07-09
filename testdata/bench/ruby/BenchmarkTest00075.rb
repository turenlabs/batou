class ConfigController < ApplicationController
  def show
    name = params[:config]
    data = File.read("config/#{name}.yml")
    render plain: data
  end
end
