import groovy.json.JsonSlurper

class ImportController {
    def importData() {
        def body = request.reader.text
        def data = new JsonSlurper().parseText(body)
        render "Imported ${data.size()} records"
    }
}
