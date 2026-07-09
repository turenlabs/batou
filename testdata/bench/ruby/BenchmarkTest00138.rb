class PaymentController < ApplicationController
  def complete
    process_payment(params[:payment_id])
    redirect_to order_path(params[:payment_id])
  end
end
