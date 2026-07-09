class DataController {
    def transform() {
        def rule = params.transform_rule
        def data = params.data
        def transforms = [upper: { it.toUpperCase() }, lower: { it.toLowerCase() }]
        def fn = transforms[rule]
        def result = fn ? fn(data) : data
        render result
    }
}
