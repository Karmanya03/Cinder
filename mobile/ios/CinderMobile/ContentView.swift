import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var inputURL: URL?
    @State private var outputURL: URL?
    @State private var importing = false
    @State private var exporting = false
    @State private var sharing = false
    @State private var status = "Choose a document from Files to begin."
    @State private var working = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Text("Cinder").font(.largeTitle.bold())
                Text("Lossless snapshots, made mobile.").foregroundStyle(.secondary)
                Button("Choose source") { importing = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(working)
                Button("Compress to…") { exporting = true }
                    .buttonStyle(.bordered)
                    .disabled(inputURL == nil || working)
                Text(status).font(.callout).foregroundStyle(.secondary)
                if let outputURL, !working {
                    Button("Share archive") { sharing = true }
                        .buttonStyle(.bordered)
                }
                Spacer()
            }
            .padding(24)
            .navigationTitle("Cinder")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    inputURL = urls.first
                    status = "Source selected. Choose an output archive."
                case .failure(let error): status = "Import failed: \(error.localizedDescription)"
                }
            }
            .fileExporter(isPresented: $exporting, document: EmptyArchiveDocument(), contentType: .data, defaultFilename: "snapshot.cnd") { result in
                switch result {
                case .success(let url): outputURL = url; runCompression(to: url)
                case .failure(let error): status = "Output selection failed: \(error.localizedDescription)"
                }
            }
            .sheet(isPresented: $sharing) {
                if let outputURL { ShareSheet(items: [outputURL]) }
            }
        }
    }

    private func runCompression(to destination: URL) {
        guard let inputURL else { return }
        working = true
        status = "Compressing securely in the background…"
        DispatchQueue.global(qos: .userInitiated).async {
            let accessed = inputURL.startAccessingSecurityScopedResource()
            defer { if accessed { inputURL.stopAccessingSecurityScopedResource() } }
            do {
                let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".cnd")
                try CinderNative.compress(input: inputURL, output: temporary)
                try FileManager.default.removeItem(at: destination)
                try FileManager.default.copyItem(at: temporary, to: destination)
                try? FileManager.default.removeItem(at: temporary)
                DispatchQueue.main.async { working = false; status = "Archive created successfully." }
            } catch {
                DispatchQueue.main.async { working = false; status = "Compression failed: \(error.localizedDescription)" }
            }
        }
    }
}

struct EmptyArchiveDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    init(configuration: ReadConfiguration) throws {}
    init() {}
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: Data()) }
}
