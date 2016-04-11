import asynchttpserver, asyncdispatch
import strtabs

var server = newAsyncHttpServer()
proc cb(req: Request) {.async.} =
        if hasKey(req.headers, "test"):
                echo(req.headers["test"])
        await req.respond(Http403, "Access Denied")
waitFor server.serve(Port(8080), cb)
