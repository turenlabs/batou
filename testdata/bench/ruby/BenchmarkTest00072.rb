class LogsController < ApplicationController
  def show
    log = File.basename(params[:log])
    base = Rails.root.join("logs").to_s
    full = File.expand_path(log, base)
    return head(:forbidden) unless full.start_with?(base)
    render plain: File.read(full)
  end
end
