class ProfilesController < ApplicationController
  def show
    @bio = params[:bio]
    render inline: "<div><%= raw(@bio) %></div>"
  end
end
