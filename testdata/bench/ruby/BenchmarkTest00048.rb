class DeployController < ApplicationController
  def run
    allowed_branches = %w[main staging production]
    branch = params[:branch]
    return head(:bad_request) unless allowed_branches.include?(branch)
    system("git", "checkout", branch)
    render plain: "deployed"
  end
end
