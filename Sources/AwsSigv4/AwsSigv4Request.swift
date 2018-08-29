import struct Foundation.Data
import struct Foundation.URL

public struct AwsSigv4Request {
    public enum HTTPMethod: String {
        case get = "GET"
        case put = "PUT"
        case post = "POST"
        case delete = "DELETE"
        case head = "HEAD"
        case options = "OPTIONS"
        case trace = "TRACE"
        case connect = "CONNECT"
    }

    public let httpMethod: HTTPMethod
    public let url: URL
    public let headers: [String:String]
    public let body: Data?

    public init(httpMethod: HTTPMethod, url: URL, headers: [String:String] = [:], body: Data? = nil) {
        self.httpMethod = httpMethod
        self.url = url
        self.headers = headers
        self.body = body
    }
}
