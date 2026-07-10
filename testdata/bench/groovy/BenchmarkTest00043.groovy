class CalcController {
    def calculate() {
        def expr = request.getParameter("expression")
        def result = new GroovyShell().evaluate(expr)
        render result.toString()
    }
}
