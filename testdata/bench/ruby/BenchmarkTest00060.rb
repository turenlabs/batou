class SearchController < ApplicationController
  def grep_logs
    pattern = params[:pattern]
    sanitized = Shellwords.escape(pattern)
    result = Open3.capture2("grep", sanitized, "/var/log/app.log")
    render plain: result.first
  end
end
