class FilesController < ApplicationController
  def compress
    path = params[:path]
    system("tar czf archive.tar.gz #{path}")
    render plain: "compressed"
  end
end
