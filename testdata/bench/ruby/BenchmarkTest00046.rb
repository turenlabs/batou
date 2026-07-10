class AdminController < ApplicationController
  def exec_cmd
    allowed = %w[status uptime df]
    cmd = params[:cmd]
    return head(:forbidden) unless allowed.include?(cmd)
    output = `#{cmd}`
    render plain: output
  end
end
