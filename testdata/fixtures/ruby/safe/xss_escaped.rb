# Safe: Properly escaped output, sanitize helper, ERB auto-escaping
# Expected: No findings for GTSS-XSS-004 or GTSS-XSS-008

class CommentsController < ApplicationController
  def show
    @comment = Comment.find(params[:id])
    # Uses ERB default auto-escaping via <%= %>
  end

  def preview
    @preview = sanitize(params[:content])
  end

  def render_message
    message = ERB::Util.html_escape(params[:message])
    render html: message
  end

  def safe_output
    content = params[:content]
    @safe = ActionController::Base.helpers.strip_tags(content)
  end
end
