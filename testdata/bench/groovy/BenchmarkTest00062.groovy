import groovy.json.JsonSlurper

def data = request.reader.text
def slurper = new JsonSlurper()
def obj = slurper.parseText(data)
