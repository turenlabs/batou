class EvalController {
    def version() {
        def result = GroovySystem.version
        render "Groovy version: ${result}"
    }
}
