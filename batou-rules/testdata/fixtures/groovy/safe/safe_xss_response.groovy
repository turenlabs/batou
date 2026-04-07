// Safe: XSS prevention via encoding and parameterized rendering
class SafeController {
    def show() {
        def name = request.getParameter("name")
        def safe = HtmlUtils.htmlEscape(name)
        response.getWriter().write(safe)
    }

    def display() {
        def input = request.getParameter("content")
        def safe = input.encodeAsHTML()
        response.getWriter().println(safe)
    }

    def preview() {
        def html = params.html
        def safe = html.encodeAsHTML()
        render(text: safe)
    }

    def logSafe() {
        def action = request.getParameter("action")
        def sanitized = action.replaceAll("[\n\r]", "")
        log.info(sanitized)
    }

    def safeLdap() {
        def filter = request.getParameter("filter")
        def safe = LdapEncoder.filterEncode(filter)
        InitialDirContext ctx = new InitialDirContext(env)
        ctx.search("ou=users", safe, controls)
    }

    def safeRedirect() {
        def url = params.returnUrl
        def valid = new URL(url).toURI()
        redirect(url: valid.toString())
    }
}
