import org.yaml.snakeyaml.Yaml

class ConfigController {
    def upload() {
        def content = params.yaml_content
        def yaml = new Yaml()
        def config = yaml.load(content)
        render config as JSON
    }
}
