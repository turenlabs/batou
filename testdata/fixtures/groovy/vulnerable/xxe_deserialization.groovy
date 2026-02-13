// Vulnerable: XXE via XmlSlurper/XmlParser and insecure deserialization
class XmlService {
    def parseXml(String xml) {
        def root = new XmlSlurper().parseText(xml)
        return root.name()
    }

    def parseWithParser(String xml) {
        def root = new XmlParser().parseText(xml)
        return root.name()
    }
}

class Serializer {
    def deserialize(InputStream input) {
        def ois = new ObjectInputStream(input)
        return ois.readObject()
    }

    def deserializeXml(String xml) {
        def xstream = new XStream()
        return xstream.fromXML(xml)
    }

    def loadYaml(String yamlStr) {
        def yaml = new Yaml()
        return yaml.load(yamlStr)
    }
}
