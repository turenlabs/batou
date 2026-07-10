class SearchController < ApplicationController
  def results
    term = params[:q]
    @items = Item.where("description LIKE ?", "%#{term}%")
    render json: @items
  end
end
