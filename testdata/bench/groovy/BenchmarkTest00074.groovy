import groovy.json.JsonSlurper

class DataController {
    def load() {
        def file = params.file
        def content = new File("/app/data/${file}").text
        def obj = new JsonSlurper().parseText(content)
        render obj.toString()
    }
}
