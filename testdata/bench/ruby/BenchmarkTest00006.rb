class ReportsController < ApplicationController
  def show
    id = params[:id].to_i
    @report = Report.find(id)
    render json: @report
  end
end
