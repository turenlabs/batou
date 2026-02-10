# Vulnerable: ERB template with unescaped output and reflected XSS
# Expected: GTSS-XSS-004 (UnescapedTemplateOutput), GTSS-XSS-011 (ReflectedXSS)

class SearchController < ApplicationController
  def results
    @query = params[:q]
    render inline: "<h1>Search results for: <%== @query %></h1>"
  end

  def echo
    render html: params[:message], layout: false
  end

  def profile
    render inline: "<div class='bio'><%= raw(params[:bio]) %></div>"
  end

  def greeting
    name = params[:name]
    render html: "Welcome, #{name}".html_safe
  end

  def feedback
    comment = params[:comment]
    render text: params[:feedback]
  end
end
