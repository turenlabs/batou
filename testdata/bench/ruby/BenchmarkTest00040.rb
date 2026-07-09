class FeedbackController < ApplicationController
  def show
    @feedback = params[:text]
    render json: { feedback: @feedback }
  end
end
