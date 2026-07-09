class ToolsController < ApplicationController
  def ping
    host = params[:host]
    system("ping", "-c", "3", host)
    render plain: "done"
  end
end
