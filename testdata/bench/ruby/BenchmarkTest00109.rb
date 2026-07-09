class BackupController < ApplicationController
  def restore
    file = params[:file]
    data = YAML.load(File.read(file))
    render json: data
  end
end
