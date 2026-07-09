class CacheController < ApplicationController
  def load
    key = params[:key]
    raw = Redis.current.get(key)
    obj = JSON.parse(raw)
    render json: obj
  end
end
