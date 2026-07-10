import com.thoughtworks.xstream.XStream

node {
    def xml = readFile('data.xml')
    def xstream = new XStream()
    def config = xstream.fromXML(xml)
    echo "Loaded: ${config}"
}
