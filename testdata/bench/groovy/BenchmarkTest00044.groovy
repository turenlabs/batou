class CalcController {
    def calculate() {
        def a = params.a?.toInteger() ?: 0
        def b = params.b?.toInteger() ?: 0
        def result = a + b
        render result.toString()
    }
}
