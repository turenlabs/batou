class ReportsController < ApplicationController
  def show
    id = params[:id]
    @report = ActiveRecord::Base.connection.execute("SELECT * FROM reports WHERE id = #{id}")
    render json: @report
  end
end
