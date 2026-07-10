class RunController {
    def execute() {
        def a = params.a?.toDouble() ?: 0
        def b = params.b?.toDouble() ?: 0
        def result = a * b
        render result.toString()
    }
}
