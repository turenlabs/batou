class ReportsController < ApplicationController
  def generate
    allowed_formats = %w[pdf html]
    format = params[:format]
    return head(:bad_request) unless allowed_formats.include?(format)
    system("wkhtmltopdf", "--format", format, "report.html", "report.pdf")
    render plain: "generated"
  end
end
