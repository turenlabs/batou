import groovy.json.JsonSlurper

class APIController {
    def execute() {
        def body = request.reader.text
        def data = new JsonSlurper().parseText(body)
        render data.toString()
    }
}
