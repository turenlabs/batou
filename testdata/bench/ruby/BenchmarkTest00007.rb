class SearchController < ApplicationController
  def results
    term = params[:q]
    @items = Item.find_by_sql("SELECT * FROM items WHERE description LIKE '%#{term}%'")
    render json: @items
  end
end
