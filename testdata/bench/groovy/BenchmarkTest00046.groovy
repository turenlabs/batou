import groovy.text.SimpleTemplateEngine

class TemplateController {
    def render() {
        def name = params.name
        def engine = new SimpleTemplateEngine()
        def template = engine.createTemplate('Hello ${name}')
        render template.make([name: name]).toString()
    }
}
