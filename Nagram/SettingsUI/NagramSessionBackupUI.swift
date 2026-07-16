import AccountContext
import Display
import Foundation
import NagramStrings
import SwiftSignalKit
import TelegramCore
import UIKit
import UniformTypeIdentifiers

// MARK: NAGRAM — Deliberately hidden session recovery UI, unlocked from the version row.
final class NagramSessionBackupCoordinator: NSObject, UIDocumentPickerDelegate {
    private let context: AccountContext
    private weak var parent: UIViewController?
    private let operationDisposable = MetaDisposable()

    init(context: AccountContext, parent: UIViewController) {
        self.context = context
        self.parent = parent
    }

    deinit {
        self.operationDisposable.dispose()
    }

    func showMenu() {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.Title"), message: self.text("Nagram.SessionBackup.Warning"), preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.SaveKeychain"), style: .default, handler: { [weak self] _ in
            self?.saveToKeychain()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.RestoreKeychain"), style: .default, handler: { [weak self] _ in
            self?.restoreFromKeychain()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Export"), style: .default, handler: { [weak self] _ in
            self?.requestExportPassword()
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Import"), style: .default, handler: { [weak self] _ in
            self?.importFile()
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
            } catch {
                self?.showResult(key: "Nagram.SessionBackup.Failed")
            }
        }, error: { [weak self] _ in
            self?.showResult(key: "Nagram.SessionBackup.Failed")
        }))
    }

    private func restoreFromKeychain() {
        do {
            guard let archive = try NagramSessionKeychain.load(), !archive.accounts.isEmpty else {
                self.showResult(key: "Nagram.SessionBackup.NotFound")
                return
            }
            self.showAccountSelection(backups: archive.accounts)
        } catch {
            self.showResult(key: "Nagram.SessionBackup.Failed")
        }
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
                    let url = FileManager.default.temporaryDirectory.appendingPathComponent("nagram-sessions-\(archive.accounts.count).nagramsession")
                    try Data(encoded.utf8).write(to: url, options: .atomic)
                    DispatchQueue.main.async {
                        self?.share(url: url)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.showResult(key: "Nagram.SessionBackup.Failed")
                    }
                }
            }
        }, error: { [weak self] _ in
            self?.showResult(key: "Nagram.SessionBackup.Failed")
        }))
    }

    private func importFile() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [UTType.data], asCopy: true)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        self.parent?.present(picker, animated: true)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first, let encoded = try? String(contentsOf: url, encoding: .utf8) else {
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

    private func showRestoreWarning(backups: [NagramSessionBackup]) {
        let alert = UIAlertController(title: self.text("Nagram.SessionBackup.ConfirmRestore"), message: self.text("Nagram.SessionBackup.RestoreWarning"), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Restore"), style: .destructive, handler: { [weak self] _ in
            self?.restore(backups: backups)
        }))
        alert.addAction(UIAlertAction(title: self.text("Nagram.SessionBackup.Cancel"), style: .cancel))
        self.present(alert)
    }

    private func restore(backups: [NagramSessionBackup]) {
        self.operationDisposable.set((nagramRestoreSessionArchive(context: self.context, backups: backups)
        |> deliverOnMainQueue).start(next: { [weak self] _ in
            self?.showResult(key: "Nagram.SessionBackup.Restored")
        }, error: { [weak self] _ in
            self?.showResult(key: "Nagram.SessionBackup.Failed")
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
        self.parent?.present(controller, animated: true)
    }

    private func text(_ key: String) -> String {
        let language = self.context.sharedContext.currentPresentationData.with { $0 }.strings.baseLanguageCode
        return ngI18n(key, language)
    }
}
