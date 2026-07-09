import Vapor
import Leaf

func handler035(_ req: Request) throws -> EventLoopFuture<View> {
    struct Context: Encodable { var title: String; var items: [String] }
    let title: String = try req.query.get(at: "title")
    let ctx = Context(title: title, items: [])
    return req.view.render("index", ctx)
}
