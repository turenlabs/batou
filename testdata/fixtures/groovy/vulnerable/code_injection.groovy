// Vulnerable: Code injection via GroovyShell and Eval
class ScriptRunner {
    def evaluateScript(String userScript) {
        new GroovyShell().evaluate(userScript)
    }

    def parseScript(String code) {
        def shell = new GroovyShell()
        def script = shell.parse(code)
        script.run()
    }

    def evalExpression(String expr) {
        Eval.me(expr)
    }

    def evalWithBinding(String expr, int x) {
        Eval.x(x, expr)
    }

    def runExternalScript(String scriptName) {
        def engine = new GroovyScriptEngine("scripts/")
        engine.run(scriptName, new Binding())
    }
}
