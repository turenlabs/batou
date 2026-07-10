class DocsController < ApplicationController
  def show
    doc = params[:doc]
    File.open("docs/#{doc}") do |f|
      render plain: f.read
    end
  end
end
