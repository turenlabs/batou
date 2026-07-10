class TemplateController {
    def render() {
        def template = params.template
        def output = Eval.me(template)
        render output.toString()
    }
}
