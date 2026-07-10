import Vapor
import Leaf

func handler031(_ req: Request) throws -> EventLoopFuture<View> {
    let name = try req.parameters.require("name")
    return req.view.render("greeting", ["name": name])
}
