class FilesController < ApplicationController
  def compress
    path = params[:path]
    safe_path = File.expand_path(path, Rails.root.join("uploads"))
    return head(:forbidden) unless safe_path.start_with?(Rails.root.join("uploads").to_s)
    system("tar", "czf", "archive.tar.gz", "-C", "uploads", File.basename(safe_path))
    render plain: "compressed"
  end
end
