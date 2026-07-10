node {
    def branch = params.BRANCH
    "git checkout ${branch}".execute()
}
