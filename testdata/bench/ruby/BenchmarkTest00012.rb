class ProductsController < ApplicationController
  def filter
    category = params[:category]
    @products = Product.where(category: category, active: true)
    render json: @products
  end
end
