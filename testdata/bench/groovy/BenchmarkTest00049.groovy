class DataController {
    def transform() {
        def rule = params.transform_rule
        def data = params.data
        def result = Eval.me("data", data, rule)
        render result
    }
}
