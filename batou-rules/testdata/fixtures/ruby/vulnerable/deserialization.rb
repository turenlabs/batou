# Vulnerable: Unsafe deserialization via Marshal.load on user input
# Expected: Taint sink match for ruby.marshal.load (CWE-502)

class SessionController < ApplicationController
  def restore
    cookie_data = cookies[:session_data]
    decoded = Base64.decode64(cookie_data)
    @session_obj = Marshal.load(decoded)
    render json: @session_obj
  end

  def import_data
    raw_data = request.body.read
    @imported = Marshal.load(raw_data)
    render json: { status: "imported", count: @imported.size }
  end

  def deserialize_cache
    cached = params[:cache_blob]
    decoded = Base64.decode64(cached)
    @obj = Marshal.load(decoded)
    render json: @obj
  end
end
