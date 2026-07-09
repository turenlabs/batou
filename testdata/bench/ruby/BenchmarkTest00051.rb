class ReportsController < ApplicationController
  def generate
    format = params[:format]
    exec("wkhtmltopdf --format #{format} report.html report.pdf")
    render plain: "generated"
  end
end
