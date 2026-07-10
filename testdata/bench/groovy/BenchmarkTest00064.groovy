import javax.xml.parsers.SAXParserFactory

def xml = request.getParameter("data")
def factory = SAXParserFactory.newInstance()
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
def slurper = new XmlSlurper(factory.newSAXParser())
def obj = slurper.parseText(xml)
