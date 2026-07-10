import javax.script.ScriptEngineManager

class EvalController {
    def run() {
        def code = params.code
        def engine = new ScriptEngineManager().getEngineByName("groovy")
        def result = engine.eval(code)
        render result.toString()
    }
}
