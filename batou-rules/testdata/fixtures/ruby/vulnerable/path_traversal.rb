# Vulnerable: Path traversal via send_file with user-controlled path
# Expected: GTSS-TRV-001 (Path Traversal)

class DocumentsController < ApplicationController
  def download
    filename = params[:filename]
    send_file Rails.root.join("uploads", filename)
  end

  def show
    path = params[:path]
    file_path = File.join(Rails.root, "documents", path)
    send_file file_path
  end

  def read
    name = params[:name]
    content = File.read("/var/data/reports/#{name}")
    render plain: content
  end

  def avatar
    user_file = params[:avatar]
    send_file File.join("/uploads/avatars", user_file)
  end
end
