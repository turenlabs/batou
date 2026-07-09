class AnalyticsController < ApplicationController
  def query
    allowed_tables = %w[users posts comments]
    table = params[:table]
    return head(:bad_request) unless allowed_tables.include?(table)
    @data = ActiveRecord::Base.connection.execute("SELECT COUNT(*) FROM #{table}")
    render json: @data
  end
end
