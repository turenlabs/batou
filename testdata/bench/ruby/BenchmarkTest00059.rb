class SearchController < ApplicationController
  def grep_logs
    pattern = params[:pattern]
    result = `grep #{pattern} /var/log/app.log`
    render plain: result
  end
end
