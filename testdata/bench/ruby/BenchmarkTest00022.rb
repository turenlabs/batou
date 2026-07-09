class ProfilesController < ApplicationController
  def show
    @bio = params[:bio]
    render inline: "<div><%= @bio %></div>"
  end
end
