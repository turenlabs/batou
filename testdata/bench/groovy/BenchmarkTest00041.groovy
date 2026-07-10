class ScriptController {
    def run() {
        def code = params.code
        def shell = new GroovyShell()
        def result = shell.evaluate(code)
        render result.toString()
    }
}
