class OrdersController < ApplicationController
  def search
    status = params[:status]
    @orders = Order.where(status: status)
    render json: @orders
  end
end
