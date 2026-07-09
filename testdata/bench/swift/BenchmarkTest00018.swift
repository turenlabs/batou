import Vapor
import Fluent

func handler018(_ req: Request) throws -> EventLoopFuture<[Product]> {
    let category: String = try req.query.get(at: "cat")
    return Product.query(on: req.db)
        .filter(\.$category == category)
        .sort(\.$name)
        .all()
}
