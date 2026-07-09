class WebhookController < ApplicationController
  def receive
    payload = params[:yaml_payload]
    data = YAML.load(payload)
    process_webhook(data)
    render json: { status: "ok" }
  end
end
