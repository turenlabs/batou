class FilterController {
    def apply() {
        def filter = params.filter
        def allowed = ["even", "odd", "positive"]
        if (!(filter in allowed)) {
            render "Invalid filter"
            return
        }
        render "Applied: ${filter}"
    }
}
