import groovy.json.JsonSlurper

class SessionController {
    def restore() {
        def encoded = params.session_data
        def json = new String(encoded.decodeBase64())
        def session = new JsonSlurper().parseText(json)
        render session.toString()
    }
}
