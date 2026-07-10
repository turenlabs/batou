class PostController {
    def save() {
        def post = new Post(title: params.title, body: params.body)
        post.save(flush: true)
        redirect(action: "show", id: post.id)
    }
}
