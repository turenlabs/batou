class FilterController {
    def apply() {
        def filter = params.filter
        def items = [1, 2, 3, 4, 5]
        def result = Eval.x(items, filter)
        render result.toString()
    }
}
