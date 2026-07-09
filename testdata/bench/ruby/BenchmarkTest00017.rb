class AnalyticsController < ApplicationController
  def query
    table = params[:table]
    @data = ActiveRecord::Base.connection.execute("SELECT COUNT(*) FROM #{table}")
    render json: @data
  end
end
