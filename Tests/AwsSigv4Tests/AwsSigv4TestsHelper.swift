import class Foundation.FileManager

struct AwsSigv4TestsHelper {
    static func workdir() -> String {
        let dir: String

        #if Xcode
        let file = #file
        dir = file.components(separatedBy: "/Tests").first ?? FileManager.default.currentDirectoryPath
        #else
        dir = FileManager.default.currentDirectoryPath
        #endif

        return dir.hasSuffix("/") ? dir : dir + "/"
    }
}
