class PreviewController < ApplicationController
  def show
    template = params[:template]
    render plain: template
  end
end
