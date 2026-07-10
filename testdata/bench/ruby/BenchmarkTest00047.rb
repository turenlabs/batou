class DeployController < ApplicationController
  def run
    branch = params[:branch]
    system("git checkout #{branch} && make deploy")
    render plain: "deployed"
  end
end
