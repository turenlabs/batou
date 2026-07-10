import groovy.json.JsonSlurper

node {
    def json = readFile('data.json')
    def config = new JsonSlurper().parseText(json)
    echo "Loaded: ${config}"
}
