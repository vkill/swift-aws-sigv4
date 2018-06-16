import struct Foundation.CharacterSet

public final class AwsSigv4Signer {
    private let service: String
    private let region: String
    private let credentials: AwsSigv4Credentials
    private let unsignedHeaderKeys: Set<String>

    private let uriEscapePath = true
    private let applyChecksumHeader = true

    public static var queryAllowed = CharacterSet(charactersIn: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~=&")
    public static var pathAllowed = CharacterSet(charactersIn: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~/")

    public init(_ service: String, _ region: String, _ credentials: AwsSigv4Credentials, unsignedHeaderKeys: [String] = []) {
        self.service = service
        self.region = region
        self.credentials = credentials

        var unsignedHeaderKeys = Set<String>(unsignedHeaderKeys.map{ $0.lowercased() })
        unsignedHeaderKeys.insert("authorization")
        unsignedHeaderKeys.insert("x-amzn-trace-id")
        self.unsignedHeaderKeys = unsignedHeaderKeys
    }
}
