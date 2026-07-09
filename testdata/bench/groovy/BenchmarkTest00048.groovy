class PluginController {
    def load() {
        def name = params.name
        def result = "Hello, " + name.replaceAll("[^a-zA-Z]", "")
        render result
    }
}
