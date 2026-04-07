// Vulnerable: XSS via response writer and Grails render
class UserController {
    def show() {
        def name = request.getParameter("name")
        response.getWriter().write(name)
    }

    def display() {
        def input = request.getParameter("content")
        response.getWriter().println(input)
    }

    def preview() {
        def html = params.html
        render(text: html)
    }

    def stream() {
        def data = request.getParameter("data")
        response.outputStream.write(data.bytes)
    }

    def raw() {
        def content = request.getParameter("body")
        response.getWriter().print(content)
    }
}
