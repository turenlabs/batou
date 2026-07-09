class LinksController < ApplicationController
  def go
    url = params[:url]
    redirect_to params[:url]
  end
end
