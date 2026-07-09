class ProductsController < ApplicationController
  def filter
    category = params[:category]
    @products = Product.where("category = '#{category}' AND active = true")
    render json: @products
  end
end
