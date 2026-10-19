import Foundation

enum CinderNative {
    enum Error: Swift.Error { case bridgeFailed(Int32) }

    static func compress(input: URL, output: URL) throws {
        let code = input.path.withCString { inputPath in
            output.path.withCString { outputPath in
                cinder_compress_path(inputPath, outputPath)
            }
        }
        if code != 0 { throw Error.bridgeFailed(code) }
    }
}

@_silgen_name("cinder_compress_path")
private func cinder_compress_path(_ input: UnsafePointer<CChar>, _ output: UnsafePointer<CChar>) -> Int32
