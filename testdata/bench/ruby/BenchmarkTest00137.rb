class PaymentController < ApplicationController
  def complete
    process_payment(params[:payment_id])
    redirect_to params[:success_url]
  end
end
