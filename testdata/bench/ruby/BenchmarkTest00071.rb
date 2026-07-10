class LogsController < ApplicationController
  def show
    log = params[:log]
    content = File.read(params[:log])
    render plain: content
  end
end
