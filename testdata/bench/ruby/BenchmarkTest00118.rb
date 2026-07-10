class MigrationController < ApplicationController
  def import_legacy
    legacy_data = params[:legacy]
    objects = JSON.parse(Base64.decode64(legacy_data))
    render json: objects
  end
end
