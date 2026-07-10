class PreviewController < ApplicationController
  def show
    template = params[:template]
    render html: raw(params[:template])
  end
end
