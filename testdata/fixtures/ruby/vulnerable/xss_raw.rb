# Vulnerable: XSS via raw() and html_safe on user input
# Expected: GTSS-XSS-004 (UnescapedTemplateOutput), GTSS-XSS-008 (ServerSideRenderingXSS)

class CommentsController < ApplicationController
  def show
    @comment = Comment.find(params[:id])
    @rendered = raw(@comment.body)
  end

  def preview
    user_input = params[:content]
    @preview = raw(user_input)
  end

  def profile
    @bio = params[:bio].html_safe
  end

  def render_message
    message = params[:message]
    render html: message.html_safe
  end
end
