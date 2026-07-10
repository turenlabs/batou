class CacheController < ApplicationController
  def load
    key = params[:key]
    raw = Redis.current.get(key)
    obj = Marshal.load(raw)
    render json: obj
  end
end
