class BackupController < ApplicationController
  def create
    allowed_dbs = %w[app_production app_staging]
    db = params[:database]
    return head(:forbidden) unless allowed_dbs.include?(db)
    system("pg_dump", db, out: "backup.sql")
    render plain: "backup created"
  end
end
