class BackupController < ApplicationController
  def create
    db = params[:database]
    system("pg_dump #{db} > backup.sql")
    render plain: "backup created"
  end
end
