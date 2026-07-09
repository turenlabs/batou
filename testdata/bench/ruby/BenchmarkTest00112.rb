class ApiController < ApplicationController
  def deserialize
    body = request.raw_post
    result = JSON.parse(body)
    render json: result
  end
end
