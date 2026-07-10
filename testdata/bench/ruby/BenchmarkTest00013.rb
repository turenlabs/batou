class OrdersController < ApplicationController
  def search
    status = params[:status]
    @orders = Order.find_by_sql("SELECT * FROM orders WHERE status = '#{status}'")
    render json: @orders
  end
end
