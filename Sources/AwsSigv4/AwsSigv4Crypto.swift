import struct Foundation.Data

public protocol AwsSigv4Crypto {
    func sha256Digest(_ value: Data) throws -> Data

    func hmacSHA256Digest(_ key: Data, _ value: Data) throws -> Data
}
