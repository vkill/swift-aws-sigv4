public struct AwsSigv4Signature {
    public let headers: [String: String]
    public let stringToSign: String
    public let canonicalRequest: String
    public let contentSha256: String
}
