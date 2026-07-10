class BackupController < ApplicationController
  def restore
    file = params[:file]
    safe_path = Rails.root.join("backups", File.basename(file))
    data = YAML.safe_load_file(safe_path.to_s)
    render json: data
  end
end
