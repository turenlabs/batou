// Vulnerable: Command injection via GString .execute()
class CommandRunner {
    def runUserCommand(String userInput) {
        def output = "ls -la ${userInput}".execute().text
        return output
    }

    def runWithList(String dir) {
        ["ls", "-la", dir].execute()
    }

    def runWithRuntime(String cmd) {
        Runtime.getRuntime().exec(cmd)
    }

    def runWithProcessBuilder(String cmd) {
        def pb = new ProcessBuilder(cmd.split(" "))
        pb.start()
    }
}
