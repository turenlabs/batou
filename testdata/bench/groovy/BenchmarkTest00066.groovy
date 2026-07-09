import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

node {
    def content = readFile('config.yaml')
    def yaml = new Yaml(new SafeConstructor())
    def config = yaml.load(content)
}
