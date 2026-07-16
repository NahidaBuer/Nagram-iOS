import AccountContext
import CryptoKit
import Foundation
import MtProtoKit
import Security
import SwiftSignalKit
import TelegramCore

// MARK: NAGRAM — Versioned session recovery data. Secret chats are intentionally not included.
struct NagramSessionBackup: Codable {
    let version: Int
    let createdAt: Int64
    let testingEnvironment: Bool
    let sortOrder: Int32
    let isPrimary: Bool
    let label: String
    let data: AccountBackupData

    init(testingEnvironment: Bool, sortOrder: Int32, isPrimary: Bool, label: String, data: AccountBackupData) {
        self.version = 1
        self.createdAt = Int64(Date().timeIntervalSince1970)
        self.testingEnvironment = testingEnvironment
        self.sortOrder = sortOrder
        self.isPrimary = isPrimary
        self.label = label
        self.data = data
    }
}

struct NagramSessionArchive: Codable {
    let version: Int
    let createdAt: Int64
    let accounts: [NagramSessionBackup]

    init(accounts: [NagramSessionBackup]) {
        self.version = 1
        self.createdAt = Int64(Date().timeIntervalSince1970)
        self.accounts = accounts
    }
}

enum NagramSessionBackupError: Error {
    case invalidPassword
    case invalidFile
    case keyDerivationFailed
    case keychain(OSStatus)
    case noBackup
}

private struct NagramEncryptedSessionEnvelope: Codable {
    let version: Int
    let kdf: String
    let rounds: Int
    let salt: Data
    let sealedBox: Data
}

enum NagramSessionBackupCrypto {
    static let minimumPasswordLength = 6
    private static let rounds = 600_000

    static func encrypt(_ archive: NagramSessionArchive, password: String) throws -> String {
        guard password.count >= minimumPasswordLength else {
            throw NagramSessionBackupError.invalidPassword
        }
        var salt = Data(count: 16)
        let randomStatus = salt.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw NagramSessionBackupError.keyDerivationFailed
        }
        let key = try deriveKey(password: password, salt: salt, rounds: rounds)
        let plaintext = try JSONEncoder().encode(archive)
        let sealedBox = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealedBox.combined else {
            throw NagramSessionBackupError.invalidFile
        }
        let envelope = NagramEncryptedSessionEnvelope(version: 1, kdf: "PBKDF2-HMAC-SHA512", rounds: rounds, salt: salt, sealedBox: combined)
        return try JSONEncoder().encode(envelope).base64EncodedString()
    }

    static func decrypt(_ encoded: String, password: String) throws -> NagramSessionArchive {
        guard password.count >= minimumPasswordLength,
              let envelopeData = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)),
              let envelope = try? JSONDecoder().decode(NagramEncryptedSessionEnvelope.self, from: envelopeData),
              envelope.version == 1,
              envelope.kdf == "PBKDF2-HMAC-SHA512",
              envelope.rounds >= 100_000 && envelope.rounds <= 2_000_000 else {
            throw NagramSessionBackupError.invalidFile
        }
        do {
            let key = try deriveKey(password: password, salt: envelope.salt, rounds: envelope.rounds)
            let sealedBox = try AES.GCM.SealedBox(combined: envelope.sealedBox)
            let plaintext = try AES.GCM.open(sealedBox, using: key)
            let archive = try JSONDecoder().decode(NagramSessionArchive.self, from: plaintext)
            guard archive.version == 1, !archive.accounts.isEmpty, archive.accounts.count <= 20,
                  archive.accounts.allSatisfy({ $0.version == 1 }) else {
                throw NagramSessionBackupError.invalidFile
            }
            return archive
        } catch let error as NagramSessionBackupError {
            throw error
        } catch {
            throw NagramSessionBackupError.invalidPassword
        }
    }

    private static func deriveKey(password: String, salt: Data, rounds: Int) throws -> SymmetricKey {
        guard let passwordData = password.data(using: .utf8), let derived = MTPBKDF2(passwordData, salt, Int32(rounds)), derived.count >= 32 else {
            throw NagramSessionBackupError.keyDerivationFailed
        }
        return SymmetricKey(data: derived.prefix(32))
    }
}

enum NagramSessionKeychain {
    private static let service = "org.nagram.session-backup.v1"
    private static let account = "archive"

    static func save(_ archive: NagramSessionArchive) throws {
        let encoded = try JSONEncoder().encode(archive)
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: true
        ]
        let updateStatus = SecItemUpdate(base as CFDictionary, [kSecValueData: encoded] as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw NagramSessionBackupError.keychain(updateStatus)
        }
        var newItem = base
        newItem[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlocked
        newItem[kSecValueData] = encoded
        let status = SecItemAdd(newItem as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NagramSessionBackupError.keychain(status)
        }
    }

    static func load() throws -> NagramSessionArchive? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw NagramSessionBackupError.keychain(status)
        }
        guard let data = result as? Data else {
            throw NagramSessionBackupError.invalidFile
        }
        let archive = try JSONDecoder().decode(NagramSessionArchive.self, from: data)
        guard archive.version == 1, !archive.accounts.isEmpty, archive.accounts.count <= 20,
              archive.accounts.allSatisfy({ $0.version == 1 }) else {
            throw NagramSessionBackupError.invalidFile
        }
        return archive
    }
}

func nagramCreateSessionArchive(context: AccountContext) -> Signal<NagramSessionArchive, NagramSessionBackupError> {
    return context.sharedContext.activeAccountContexts
    |> take(1)
    |> castError(NagramSessionBackupError.self)
    |> mapToSignal { primary, accounts, _ -> Signal<NagramSessionArchive, NagramSessionBackupError> in
        let presentationData = context.sharedContext.currentPresentationData.with { $0 }
        let backups = accounts.map { _, accountContext, sortOrder in
            return combineLatest(
                accountBackupData(postbox: accountContext.account.postbox) |> take(1),
                accountContext.engine.data.get(TelegramEngine.EngineData.Item.Peer.Peer(id: accountContext.account.peerId))
            )
            |> take(1)
            |> map { data, peer -> NagramSessionBackup? in
                return data.map {
                    let label = peer?.displayTitle(strings: presentationData.strings, displayOrder: presentationData.nameDisplayOrder) ?? "\($0.peerId)"
                    return NagramSessionBackup(testingEnvironment: accountContext.account.testingEnvironment, sortOrder: sortOrder, isPrimary: accountContext.account.id == primary?.account.id, label: label, data: $0)
                }
            }
        }
        return combineLatest(backups)
        |> castError(NagramSessionBackupError.self)
        |> mapToSignal { values -> Signal<NagramSessionArchive, NagramSessionBackupError> in
            let values = values.compactMap { $0 }
            guard !values.isEmpty else {
                return .fail(.noBackup)
            }
            return .single(NagramSessionArchive(accounts: values))
        }
    }
}

private func nagramInstallOriginalSession(context: AccountContext, backup: NagramSessionBackup, makeCurrent: Bool) -> Signal<AccountRecordId, NagramSessionBackupError> {
    return context.sharedContext.accountManager.transaction { transaction -> AccountRecordId in
        if let existing = transaction.getRecords().first(where: { record in
            let hasMatchingBackup = record.attributes.contains(where: { attribute in
                if case let .backupData(value) = attribute {
                    return value.data?.peerId == backup.data.peerId
                }
                return false
            })
            let hasMatchingEnvironment = record.attributes.contains(where: { attribute in
                if case let .environment(value) = attribute {
                    return (value.environment == .test) == backup.testingEnvironment
                }
                return false
            })
            return hasMatchingBackup && hasMatchingEnvironment
        }) {
            if makeCurrent {
                transaction.setCurrentId(existing.id)
            }
            return existing.id
        }
        let maxSortOrder = transaction.getRecords().compactMap { record -> Int32? in
            for attribute in record.attributes {
                if case let .sortOrder(value) = attribute {
                    return value.order
                }
            }
            return nil
        }.max() ?? -1
        let id = transaction.createRecord([
            .environment(AccountEnvironmentAttribute(environment: backup.testingEnvironment ? .test : .production)),
            .backupData(AccountBackupDataAttribute(data: backup.data)),
            .sortOrder(AccountSortOrderAttribute(order: max(backup.sortOrder, maxSortOrder + 1)))
        ])
        if makeCurrent {
            transaction.setCurrentId(id)
        }
        return id
    }
    |> castError(NagramSessionBackupError.self)
}

func nagramRestoreSessionArchive(context: AccountContext, backups: [NagramSessionBackup]) -> Signal<[AccountRecordId], NagramSessionBackupError> {
    var uniqueKeys = Set<String>()
    let uniqueBackups = backups.sorted(by: { $0.sortOrder < $1.sortOrder }).filter { backup in
        uniqueKeys.insert("\(backup.testingEnvironment).\(backup.data.peerId)").inserted
    }
    guard !uniqueBackups.isEmpty else {
        return .fail(.noBackup)
    }

    func restore(index: Int, ids: [AccountRecordId]) -> Signal<[AccountRecordId], NagramSessionBackupError> {
        guard index < uniqueBackups.count else {
            let primaryIndex = uniqueBackups.firstIndex(where: { $0.isPrimary }) ?? 0
            return context.sharedContext.accountManager.transaction { transaction -> [AccountRecordId] in
                if ids.indices.contains(primaryIndex) {
                    transaction.setCurrentId(ids[primaryIndex])
                }
                return ids
            }
            |> castError(NagramSessionBackupError.self)
        }
        return nagramInstallOriginalSession(context: context, backup: uniqueBackups[index], makeCurrent: false)
        |> mapToSignal { id in
            restore(index: index + 1, ids: ids + [id])
        }
    }

    return restore(index: 0, ids: [])
}
