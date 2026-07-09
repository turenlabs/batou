class ApiController < ApplicationController
  def deserialize
    body = request.raw_post
    result = YAML.load(body)
    render json: result
  end
end
