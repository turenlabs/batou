import groovy.json.JsonSlurper

def url = params.config_url
def content = new URL(url).text
def config = new JsonSlurper().parseText(content)
