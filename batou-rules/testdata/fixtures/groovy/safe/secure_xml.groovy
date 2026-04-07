// Safe: Secure XML parsing with XXE protection and safe deserialization
class XmlService {
    def parseXml(String xml) {
        def slurper = new XmlSlurper()
        slurper.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        def root = slurper.parseText(xml)
        return root.name()
    }
}

class SafeSerializer {
    def loadYaml(String yamlStr) {
        def yaml = new Yaml(new SafeConstructor())
        return yaml.load(yamlStr)
    }
}
