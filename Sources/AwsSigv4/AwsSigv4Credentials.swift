public final class AwsSigv4Credentials {
    public let accessKeyID: String
    public let secretAccessKey: String
    public let sessionToken: String?

    public init(_ accessKeyID: String, _ secretAccessKey: String, _ sessionToken: String? = nil) {
        self.accessKeyID = accessKeyID
        self.secretAccessKey = secretAccessKey
        self.sessionToken = sessionToken
    }
}
