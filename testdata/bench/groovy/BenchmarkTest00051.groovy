class RunController {
    def execute() {
        def scriptName = params.script
        def engine = new GroovyScriptEngine("scripts/")
        engine.run(scriptName, new Binding())
    }
}
