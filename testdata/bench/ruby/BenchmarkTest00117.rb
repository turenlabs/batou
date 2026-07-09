class MigrationController < ApplicationController
  def import_legacy
    legacy_data = params[:legacy]
    objects = Marshal.load(Base64.decode64(legacy_data))
    render json: objects
  end
end
