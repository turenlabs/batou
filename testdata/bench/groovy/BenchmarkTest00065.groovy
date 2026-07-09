import org.yaml.snakeyaml.Yaml

node {
    def content = readFile('config.yaml')
    def yaml = new Yaml()
    def config = yaml.load(content)
}
