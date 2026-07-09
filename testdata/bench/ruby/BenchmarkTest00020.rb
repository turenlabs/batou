class TagsController < ApplicationController
  def search
    name = params[:name]
    @tags = Tag.where("name LIKE ?", "#{name}%").order(name: :asc)
    render json: @tags
  end
end
