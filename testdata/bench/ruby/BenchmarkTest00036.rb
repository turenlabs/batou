class ArticlesController < ApplicationController
  def show
    @title = params[:title]
    render inline: "<h1><%= h(@title) %></h1>"
  end
end
