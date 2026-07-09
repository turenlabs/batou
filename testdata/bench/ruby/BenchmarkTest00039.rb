class FeedbackController < ApplicationController
  def show
    @feedback = params[:text]
    render html: raw(params[:text])
  end
end
