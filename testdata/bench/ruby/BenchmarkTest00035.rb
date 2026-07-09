class ArticlesController < ApplicationController
  def show
    @title = params[:title]
    render inline: "<h1><%= raw(@title) %></h1>"
  end
end
