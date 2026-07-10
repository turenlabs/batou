import Vapor

func handler080(_ req: Request) throws -> EventLoopFuture<Response> {
    let filename = "report.pdf"
    let path = req.application.directory.publicDirectory + filename
    return req.fileio.streamFile(at: path)
}
