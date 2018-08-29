import struct Foundation.Data
import struct Foundation.CharacterSet
import struct Foundation.Date
import struct Foundation.URL
import struct Foundation.URLComponents
import class Foundation.DateFormatter
import struct Foundation.TimeZone
import struct Foundation.Locale

public struct AwsSigv4Signer {
    public enum Content {
        case unsigned
        case data(Data)

        public func sha256sum(crypto: AwsSigv4Crypto) throws -> String {
            switch self {
            case .unsigned:
                return "UNSIGNED-PAYLOAD"
            case .data(let data):
                return try crypto.sha256Digest(data).hexEncodedString()
            }
        }
    }

    private let service: String
    private let region: String
    private let credentials: AwsSigv4Credentials
    private let crypto: AwsSigv4Crypto
    private let unsignedHeaderKeys: Set<String>

    private let uriEscapePath = true
    private let applyChecksumHeader = true

    public static var queryAllowed = CharacterSet(charactersIn: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~=&")
    public static var pathAllowed = CharacterSet(charactersIn: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~/")

    public init(
        service: String,
        region: String,
        credentials: AwsSigv4Credentials,
        crypto: AwsSigv4Crypto,
        unsignedHeaderKeys: [String] = []
    ) {
        self.service = service
        self.region = region
        self.credentials = credentials
        self.crypto = crypto

        var unsignedHeaderKeys = Set<String>(unsignedHeaderKeys.map{ $0.lowercased() })
        unsignedHeaderKeys.insert("authorization")
        unsignedHeaderKeys.insert("x-amzn-trace-id")
        self.unsignedHeaderKeys = unsignedHeaderKeys
    }

    public func signRequest(request: AwsSigv4Request) throws -> AwsSigv4Signature {
        let httpMethod = request.httpMethod
        let url = request.url

        var headers = downcaseHeaders(request.headers)

        let amzDate: String
        amzDate = headers["x-amz-date"] ?? amzDateFromDate(Date())
        let datetime = amzDate

        let date: String
        date = String(amzDate[..<amzDate.index(amzDate.startIndex, offsetBy: 8)])

        let contentSha256: String
        let content: Content
        if let body = request.body {
            content = .data(body)
        } else {
            content = .unsigned
        }
        contentSha256 = try headers["x-amz-content-sha256"] ?? content.sha256sum(crypto: crypto)

        var sigv4Headers: [String:String] = [:]
        sigv4Headers["host"] = try host(url)
        sigv4Headers["x-amz-date"] = amzDate
        if let amzSecurityToken = credentials.sessionToken, !amzSecurityToken.isEmpty {
            sigv4Headers["x-amz-security-token"] = amzSecurityToken
        }
        if applyChecksumHeader {
            sigv4Headers["x-amz-content-sha256"] = contentSha256
        }

        headers.merge(sigv4Headers){ (_, new) in new }

        let creq = try canonicalRequest(httpMethod, url, headers, contentSha256)
        let sts = try stringToSign(datetime, date, creq)
        let sig = try signature(date, sts)

        sigv4Headers["authorization"] = [
            "AWS4-HMAC-SHA256 Credential=\(amzCredential(date))",
            "SignedHeaders=\(amzSignedHeaders(headers))",
            "Signature=\(sig)",
            ].joined(separator: ", ")

        return AwsSigv4Signature(
            headers: sigv4Headers,
            stringToSign: sts,
            canonicalRequest: creq,
            contentSha256: contentSha256
        )
    }

    public func presignUrl(
        httpMethod: AwsSigv4Request.HTTPMethod,
        url: URL,
        headers: [String:String] = [:],
        body: Data? = nil,
        expiresIn: Int = 900,
        date: Date? = nil
    ) throws -> URL {
        var headers = downcaseHeaders(headers)
        headers["host"] = try host(url)

        let amzDate: String
        amzDate = headers["x-amz-date"] ?? amzDateFromDate(date ?? Date())
        let datetime = amzDate

        let date: String
        date = String(amzDate[..<amzDate.index(amzDate.startIndex, offsetBy: 8)])

        let contentSha256: String
        let content: Content
        if let body = body {
            content = .data(body)
        } else {
            content = .unsigned
        }
        contentSha256 = try headers["x-amz-content-sha256"] ?? content.sha256sum(crypto: crypto)

        var urlQuerySuffixDict: [String:String] = [:]
        urlQuerySuffixDict["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
        urlQuerySuffixDict["X-Amz-Credential"] = amzCredential(date)
        urlQuerySuffixDict["X-Amz-Date"] = amzDate
        urlQuerySuffixDict["X-Amz-Expires"] = String(expiresIn)
        urlQuerySuffixDict["X-Amz-SignedHeaders"] = amzSignedHeaders(headers)
        if let amzSecurityToken = credentials.sessionToken, !amzSecurityToken.isEmpty {
            urlQuerySuffixDict["X-Amz-Security-Token"] = amzSecurityToken
        }

        var urlQuerySuffixList = [String]()
        urlQuerySuffixDict.forEach { (k, v) in
            if let k = try? urlQueryKeyOrValueEncode(k) {
                if let v = try? urlQueryKeyOrValueEncode(v) {
                    urlQuerySuffixList.append("\(k)=\(v)")
                }
            }
        }

        let urlQuerySuffixString = urlQuerySuffixList.joined(separator: "&")

        var urlStringNew = url.absoluteString
        if let query = url.query {
            if !query.isEmpty {
                urlStringNew += "&"
            }
            urlStringNew += urlQuerySuffixString
        } else {
            urlStringNew += "?"
            urlStringNew += urlQuerySuffixString
        }

        guard let urlNew = URL(string: urlStringNew) else {
            throw AwsSigv4Errors.badLogic
        }

        let creq = try canonicalRequest(httpMethod, urlNew, headers, contentSha256)
        let sts = try stringToSign(datetime, date, creq)
        let sign = try signature(date, sts)

        urlStringNew += "&"
        urlStringNew += "X-Amz-Signature=\(sign)"
        guard let urlEnd = URL(string: urlStringNew) else {
            throw AwsSigv4Errors.badLogic
        }

        return urlEnd
    }

    //
    private func downcaseHeaders(_ headers: [String:String]) -> [String:String] {
        return Dictionary(uniqueKeysWithValues: headers.map { k, v in (k.lowercased(), v) })
    }

    private func amzDateFromDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        formatter.timeZone = TimeZone(abbreviation: "UTC")
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }

    private func credentialScope(_ dateString: String) -> String {
        return [
            dateString,
            region,
            service,
            "aws4_request"
        ].joined(separator: "/")
    }

    private func amzCredential(_ dateString: String) -> String {
        return "\(credentials.accessKeyID)/\(credentialScope(dateString))"
    }

    private func amzSignedHeaders(_ headers: [String:String]) -> String {
        return headers.keys.filter{ !unsignedHeaderKeys.contains($0) }.sorted{$0.compare($1) == .orderedAscending}.joined(separator: ";")
    }

    private func urlQueryKeyOrValueEncode(_ string: String) throws -> String {
        return (string.addingPercentEncoding(withAllowedCharacters: type(of: self).queryAllowed)!)
    }

    private func host(_ url: URL) throws -> String {
        guard let host = url.host else {
            throw AwsSigv4Errors.missingHostInURL
        }
        if let port = url.port {
            return "\(host):\(port)"
        } else {
            return host
        }
    }

    private func path(_ url: URL) throws -> String {
        guard !url.path.isEmpty else {
            return "/"
        }

        if !uriEscapePath {
            return url.path
        }

        return url.path.components(separatedBy: "/").map{ $0.addingPercentEncoding(withAllowedCharacters: type(of: self).pathAllowed)! }.joined(separator: "/")
    }

    private func query(_ url: URL) throws -> String {
        if let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems {
            let items = queryItems.map({ ($0.name, try! urlQueryKeyOrValueEncode($0.value ?? "") ) })
            let encodedItems = items.map({ "\($0.0)=\($0.1)" })
            return encodedItems.sorted{$0.compare($1) == .orderedAscending}.joined(separator: "&")
        }
        return ""
    }

    private func canonicalHeaderValue(_ value: String) -> String {
        if value.range(of: "^\".*\"$", options: .regularExpression) != nil {
            return value
        } else {
            return value.replacingOccurrences(of: "\\s+", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private func canonicalHeaders(_ headers: [String:String]) -> String {
        return headers.filter{ !unsignedHeaderKeys.contains($0.key) }
            .sorted(by: {$0.key.compare($1.key) == .orderedAscending})
            .map{ "\($0.key):\(canonicalHeaderValue($0.value))" }
            .joined(separator: "\n")
    }

    private func canonicalRequest(_ httpMethod: AwsSigv4Request.HTTPMethod, _ url: URL, _ headers: [String:String], _ contentSha256: String) throws -> String {
        return [
            httpMethod.rawValue,
            try path(url),
            try query(url),
            canonicalHeaders(headers) + "\n",
            amzSignedHeaders(headers),
            contentSha256,
        ].joined(separator: "\n")
    }

    private func stringToSign(_ datetime: String, _ date: String, _ creq: String) throws -> String {
        return try [
            "AWS4-HMAC-SHA256",
            datetime,
            credentialScope(date),
            crypto.sha256Digest(Data(creq.utf8)).hexEncodedString(),
        ].joined(separator: "\n")
    }

    private func signature(_ date: String, _ sts: String) throws -> String {
        let keyDate = try crypto.hmacSHA256Digest(Data("AWS4\(credentials.secretAccessKey)".utf8), Data(date.utf8))
        let keyRegion = try crypto.hmacSHA256Digest(keyDate, Data(region.utf8))
        let keyService = try crypto.hmacSHA256Digest(keyRegion, Data(service.utf8))
        let keyCredentials = try crypto.hmacSHA256Digest(keyService, Data("aws4_request".utf8))

        return try crypto.hmacSHA256Digest(keyCredentials, Data(sts.utf8)).hexEncodedString()
    }
}
