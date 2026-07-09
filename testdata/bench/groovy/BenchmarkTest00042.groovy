import groovy.json.JsonSlurper

class ScriptController {
    def run() {
        def code = params.code
        def slurper = new JsonSlurper()
        def result = slurper.parseText(code)
        render result.toString()
    }
}
