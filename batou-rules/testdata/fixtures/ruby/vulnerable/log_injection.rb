# Vulnerable: Log injection with unsanitized user input
# Expected: GTSS-LOG-001 (UnsanitizedLogInput)

class PaymentsController < ApplicationController
  def create
    amount = params[:amount]
    Rails.logger.info "Payment initiated: amount=#{params[:amount]} user=#{params[:user_id]}"

    begin
      process_payment(amount)
      Rails.logger.info "Payment successful for params[#{params[:transaction_id]}]"
    rescue => e
      Rails.logger.error "Payment failed: #{params[:error_detail]} - #{e.message}"
    end
  end

  def refund
    Rails.logger.warn "Refund requested by user: #{params[:user_id]} for order #{params[:order_id]}"
    process_refund(params[:order_id])
  end

  def webhook
    Rails.logger.debug "Webhook received: #{request.raw_post}"
    process_webhook(request.body.read)
  end
end
