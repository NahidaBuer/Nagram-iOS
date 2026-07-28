import AccountContext
import Display
import Foundation
import LocalAuthentication
import NagramStrings
import SwiftSignalKit
import TelegramCore
import UIKit
import UniformTypeIdentifiers

// MARK: NAGRAM — Deliberately hidden session recovery UI, unlocked from the version row.
final class NagramSessionBackupCoordinator: NSObject, UIDocumentPickerDelegate {
    private enum FileImportKind {
        case encryptedArchive
        case externalDatabase
    }

    private let context: AccountContext
    private weak var parent: UIViewController?
    private weak var presentedController: UIViewController?
    private let operationDisposable = MetaDisposable()
    private var backgroundObserver: NSObjectProtocol?
    private var fileImportKind: FileImportKind?

    init(context: AccountContext, parent: UIViewController) {
        self.context = context
        self.parent = parent
        super.init()
        self.backgroundObserver = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self, let presentedController = self.presentedController, self.parent?.presentedViewController === presentedController else {
                return
            }
            presentedController.dismiss(animated: false)
        }
    }

    deinit {
        if let backgroundObserver = self.backgroundObserver {
            NotificationCenter.default.removeObserver(backgroundObserver)
        }
        self.operationDisposable.dispose()
    }

    func showMenu() {
        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            self.showResult(key: "Nagram.SessionBackup.AuthenticationUnavailable")
            return
        }
        authenticationContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: self.text("Nagram.SessionBackup.AuthenticationReason")) { [weak self] success, _ in
            DispatchQueue.main.async {
                guard let self else {
                    return
                }
                if success {
                    self.showAuthenticatedMenu()
                } else {
                    self.showResult(key: "Nagram.SessionBackup.AuthenticationFailed")
                }
            }
        }
    }

    private func showAuthenticatedMenu() {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.Title"), message: self.text("Nagram.SessionBackup.Warning"), preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.SaveKeychain"), style: .default, handler: { [weak self] _ in
            self?.saveToKeychain()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.RestoreKeychain"), style: .default, handler: { [weak self] _ in
            self?.restoreFromKeychain()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.DeleteKeychain"), style: .destructive, handler: { [weak self] _ in
            self?.confirmDeleteKeychain()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Export"), style: .default, handler: { [weak self] _ in
            self?.requestExportPassword()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Import"), style: .default, handler: { [weak self] _ in
            self?.importFile(kind: .encryptedArchive)
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.ImportDatabase"), style: .default, handler: { [weak self] _ in
            self?.importFile(kind: .externalDatabase)
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.ImportString"), style: .default, handler: { [weak self] _ in
            self?.requestSessionString()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        self.present(alert)
    }

    private func saveToKeychain() {
        self.operationDisposable.set((nagramCreateSessionArchive(context: self.context)
        |> deliverOnMainQueue).start(next: { [weak self] archive in
            do {
                try NagramSessionKeychain.save(archive)
                self?.showResult(key: "Nagram.SessionBackup.Saved")
            } catch let error as NagramSessionBackupError {
                self?.show(error: error)
            } catch {
                self?.showResult(key: "Nagram.SessionBackup.Failed")
            }
        }, error: { [weak self] error in
            self?.show(error: error)
        }))
    }

    private func restoreFromKeychain() {
        do {
            guard let archive = try NagramSessionKeychain.load() else {
                self.showResult(key: "Nagram.SessionBackup.NotFound")
                return
            }
            self.showAccountSelection(backups: archive.accounts)
        } catch let error as NagramSessionBackupError {
            self.show(error: error)
        } catch {
            self.showResult(key: "Nagram.SessionBackup.Failed")
        }
    }

    private func confirmDeleteKeychain() {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.DeleteKeychain"), message: self.text("Nagram.SessionBackup.DeleteKeychainWarning"), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Delete"), style: .destructive, handler: { [weak self] _ in
            do {
                try NagramSessionKeychain.delete()
                self?.showResult(key: "Nagram.SessionBackup.Deleted")
            } catch let error as NagramSessionBackupError {
                self?.show(error: error)
            } catch {
                self?.showResult(key: "Nagram.SessionBackup.Failed")
            }
        }))
        self.present(alert)
    }

    private func requestExportPassword() {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.Export"), message: self.text("Nagram.SessionBackup.PasswordHint"), preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = self.text("Nagram.SessionBackup.Password")
            field.isSecureTextEntry = true
            field.textContentType = .newPassword
        }
        alert.addTextField { field in
            field.placeholder = self.text("Nagram.SessionBackup.ConfirmPassword")
            field.isSecureTextEntry = true
            field.textContentType = .newPassword
        }
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Export"), style: .default, handler: { [weak self, weak alert] _ in
            guard let self, let password = alert?.textFields?.first?.text, let confirmation = alert?.textFields?.last?.text,
                  password == confirmation, password.count >= NagramSessionBackupCrypto.minimumPasswordLength else {
                self?.showResult(key: "Nagram.SessionBackup.InvalidPassword")
                return
            }
            self.export(password: password)
        }))
        self.present(alert)
    }

    private func export(password: String) {
        self.operationDisposable.set((nagramCreateSessionArchive(context: self.context)
        |> deliverOnMainQueue).start(next: { [weak self] archive in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let encoded = try NagramSessionBackupCrypto.encrypt(archive, password: password)
                    let url = FileManager.default.temporaryDirectory.appendingPathComponent("nagram-sessions-\(archive.accounts.count)-\(UUID().uuidString).nagramsession")
                    try Data(encoded.utf8).write(to: url, options: .atomic)
                    DispatchQueue.main.async {
                        self?.share(url: url)
                    }
                } catch let error as NagramSessionBackupError {
                    DispatchQueue.main.async {
                        self?.show(error: error)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.showResult(key: "Nagram.SessionBackup.Failed")
                    }
                }
            }
        }, error: { [weak self] error in
            self?.show(error: error)
        }))
    }

    private func importFile(kind: FileImportKind) {
        self.fileImportKind = kind
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [UTType.data], asCopy: true)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        self.parent?.present(picker, animated: true)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first, let kind = self.fileImportKind else {
            self.showResult(key: "Nagram.SessionBackup.InvalidFile")
            return
        }
        self.fileImportKind = nil
        switch kind {
        case .encryptedArchive:
            self.readEncryptedArchive(url: url)
        case .externalDatabase:
            self.readExternalDatabase(url: url)
        }
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        self.fileImportKind = nil
    }

    private func readEncryptedArchive(url: URL) {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
              values.isRegularFile == true,
              let fileSize = values.fileSize,
              fileSize > 0,
              fileSize <= NagramSessionBackupValidator.maximumArchiveFileSize,
              let encoded = try? String(contentsOf: url, encoding: .utf8) else {
            self.showResult(key: "Nagram.SessionBackup.InvalidFile")
            return
        }
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.Import"), message: self.text("Nagram.SessionBackup.PasswordHint"), preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = self.text("Nagram.SessionBackup.Password")
            field.isSecureTextEntry = true
            field.textContentType = .password
        }
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Import"), style: .default, handler: { [weak self, weak alert] _ in
            guard let self, let password = alert?.textFields?.first?.text else {
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let archive = try NagramSessionBackupCrypto.decrypt(encoded, password: password)
                    DispatchQueue.main.async {
                        self.showAccountSelection(backups: archive.accounts)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.showResult(key: "Nagram.SessionBackup.InvalidFileOrPassword")
                    }
                }
            }
        }))
        self.present(alert)
    }

    private func readExternalDatabase(url: URL) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let authorization = try NagramSessionDatabaseParser.parse(url)
                DispatchQueue.main.async {
                    self.handleExternalAuthorization(authorization)
                }
            } catch let error as NagramSessionBackupError {
                DispatchQueue.main.async {
                    self.show(error: error)
                }
            } catch {
                DispatchQueue.main.async {
                    self.showResult(key: "Nagram.SessionBackup.InvalidFile")
                }
            }
        }
    }

    private func requestSessionString() {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.ImportString"), message: self.text("Nagram.SessionBackup.SessionStringHint"), preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = self.text("Nagram.SessionBackup.SessionString")
            field.isSecureTextEntry = true
            field.autocorrectionType = .no
            field.autocapitalizationType = .none
            field.textContentType = .password
        }
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.ImportString"), style: .default, handler: { [weak self, weak alert] _ in
            guard let self, let value = alert?.textFields?.first?.text else {
                return
            }
            do {
                self.handleExternalAuthorization(try NagramSessionStringParser.parse(value))
            } catch let error as NagramSessionBackupError {
                self.show(error: error)
            } catch {
                self.showResult(key: "Nagram.SessionBackup.InvalidFile")
            }
        }))
        self.present(alert)
    }

    private func handleExternalAuthorization(_ authorization: NagramExternalSessionAuthorization) {
        if authorization.peerId == nil {
            self.requestTelethonPeerId(authorization)
            return
        }
        do {
            self.showExternalRestoreWarning(authorization: authorization, backup: try authorization.makeBackup())
        } catch let error as NagramSessionBackupError {
            self.show(error: error)
        } catch {
            self.showResult(key: "Nagram.SessionBackup.InvalidFile")
        }
    }

    private func requestTelethonPeerId(_ authorization: NagramExternalSessionAuthorization) {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.TelethonPeerIdTitle"), message: self.text("Nagram.SessionBackup.TelethonPeerIdHint"), preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = self.text("Nagram.SessionBackup.TelegramUserId")
            field.keyboardType = .numberPad
            field.textContentType = .none
        }
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Continue"), style: .default, handler: { [weak self, weak alert] _ in
            guard let self, let value = alert?.textFields?.first?.text, let peerId = Int64(value), peerId > 0 else {
                self?.showResult(key: "Nagram.SessionBackup.InvalidPeerId")
                return
            }
            do {
                self.showExternalRestoreWarning(authorization: authorization, backup: try authorization.makeBackup(peerId: peerId))
            } catch let error as NagramSessionBackupError {
                self.show(error: error)
            } catch {
                self.showResult(key: "Nagram.SessionBackup.InvalidFile")
            }
        }))
        self.present(alert)
    }

    private func showExternalRestoreWarning(authorization: NagramExternalSessionAuthorization, backup: NagramSessionBackup) {
        let environment = authorization.testingEnvironment ? self.text("Nagram.SessionBackup.TestEnvironment") : self.text("Nagram.SessionBackup.ProductionEnvironment")
        let details = "\(authorization.source.label)\nDC \(authorization.masterDatacenterId) · \(environment)\nUser ID \(backup.data.peerId)\n\n\(self.text("Nagram.SessionBackup.ExternalWarning"))"
        self.showRestoreWarning(backups: [backup], message: details)
    }

    private func showAccountSelection(backups: [NagramSessionBackup]) {
        guard backups.count > 1 else {
            if let backup = backups.first {
                self.showRestoreWarning(backups: [backup])
            }
            return
        }
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.SelectAccount"), message: self.text("Nagram.SessionBackup.AccountCount").replacingOccurrences(of: "%d", with: "\(backups.count)"), preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.AllAccounts"), style: .default, handler: { [weak self] _ in
            self?.showRestoreWarning(backups: backups)
        }))
        for backup in backups.sorted(by: { $0.sortOrder < $1.sortOrder }) {
            alert.addAction(UIAlertAction(title: "\(backup.label) · \(backup.data.peerId)\(backup.testingEnvironment ? " (test)" : "")", style: .default, handler: { [weak self] _ in
                self?.showRestoreWarning(backups: [backup])
            }))
        }
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        self.present(alert)
    }

    private func showRestoreWarning(backups: [NagramSessionBackup], message: String? = nil) {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.ConfirmRestore"), message: message ?? self.text("Nagram.SessionBackup.RestoreWarning"), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Restore"), style: .destructive, handler: { [weak self] _ in
            self?.restore(backups: backups)
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        self.present(alert)
    }

    private func restore(backups: [NagramSessionBackup]) {
        let progress = UIAlertController(title: nil, message: self.text("Nagram.SessionBackup.Verifying"), preferredStyle: .alert)
        self.present(progress)
        self.operationDisposable.set((nagramRestoreSessionArchive(context: self.context, backups: backups)
        |> deliverOnMainQueue).start(next: { [weak self, weak progress] _ in
            progress?.dismiss(animated: true, completion: {
                self?.showResult(key: "Nagram.SessionBackup.Restored")
            })
        }, error: { [weak self, weak progress] error in
            progress?.dismiss(animated: true, completion: {
                self?.show(error: error)
            })
        }))
    }

    private func share(url: URL) {
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        controller.completionWithItemsHandler = { _, _, _, _ in
            try? FileManager.default.removeItem(at: url)
        }
        if let popover = controller.popoverPresentationController, let view = self.parent?.view {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.maxY, width: 1.0, height: 1.0)
        }
        self.parent?.present(controller, animated: true)
    }

    private func show(error: NagramSessionBackupError) {
        switch error {
        case .invalidPassword:
            self.showResult(key: "Nagram.SessionBackup.InvalidPassword")
        case .invalidFile:
            self.showResult(key: "Nagram.SessionBackup.InvalidFile")
        case .unsupportedFormat:
            self.showResult(key: "Nagram.SessionBackup.UnsupportedFormat")
        case .botSession:
            self.showResult(key: "Nagram.SessionBackup.BotUnsupported")
        case .missingPeerId:
            self.showResult(key: "Nagram.SessionBackup.InvalidPeerId")
        case .capacityExceeded:
            self.showResult(key: "Nagram.SessionBackup.CapacityExceeded")
        case .verificationTimedOut:
            self.showResult(key: "Nagram.SessionBackup.VerificationFailed")
        case .noBackup:
            self.showResult(key: "Nagram.SessionBackup.NotFound")
        case .keyDerivationFailed, .keychain:
            self.showResult(key: "Nagram.SessionBackup.Failed")
        }
    }

    private func showResult(key: String) {
        let alert = UIAlertController(title: nil, message: self.text(key), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.OK"), style: .default))
        self.present(alert)
    }

    private func present(_ controller: UIAlertController) {
        if let popover = controller.popoverPresentationController, let view = self.parent?.view {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.maxY, width: 1.0, height: 1.0)
        }
        self.presentedController = controller
        self.parent?.present(controller, animated: true)
    }

    private func text(_ key: String) -> String {
        let language = self.context.sharedContext.currentPresentationData.with { $0 }.strings.baseLanguageCode
        return ngI18n(key, language)
    }
}
