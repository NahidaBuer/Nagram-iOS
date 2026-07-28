import AccountContext
import AccountUtils
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
    case unsupportedFormat
    case botSession
    case missingPeerId
    case capacityExceeded
    case verificationTimedOut
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

enum NagramSessionBackupValidator {
    static let maximumArchiveFileSize = 1024 * 1024
    private static let maximumPlaintextSize = 768 * 1024
    private static let maximumLabelLength = 128

    static func validate(_ archive: NagramSessionArchive) throws {
        guard archive.version == 1,
              !archive.accounts.isEmpty,
              archive.accounts.count <= maximumNumberOfAccounts,
              archive.accounts.filter({ $0.isPrimary }).count <= 1 else {
            throw NagramSessionBackupError.invalidFile
        }
        var accountKeys = Set<String>()
        for backup in archive.accounts {
            try self.validate(backup)
            guard accountKeys.insert("\(backup.testingEnvironment).\(backup.data.peerId)").inserted else {
                throw NagramSessionBackupError.invalidFile
            }
        }
        guard let encoded = try? JSONEncoder().encode(archive), encoded.count <= self.maximumPlaintextSize else {
            throw NagramSessionBackupError.invalidFile
        }
    }

    static func validate(_ backup: NagramSessionBackup) throws {
        guard backup.version == 1,
              backup.data.peerId > 0,
              !backup.label.isEmpty,
              backup.label.count <= self.maximumLabelLength else {
            throw NagramSessionBackupError.invalidFile
        }
        let validDatacenters = backup.testingEnvironment ? 1 ... 3 : 1 ... 5
        guard validDatacenters.contains(Int(backup.data.masterDatacenterId)),
              backup.data.masterDatacenterKey.count == 256,
              nagramAuthKeyId(backup.data.masterDatacenterKey) == backup.data.masterDatacenterKeyId else {
            throw NagramSessionBackupError.invalidFile
        }
        for (id, key) in backup.data.additionalDatacenterKeys {
            guard id == key.id,
                  (1 ... 10).contains(Int(id)),
                  id != backup.data.masterDatacenterId,
                  key.key.count == 256,
                  nagramAuthKeyId(key.key) == key.keyId else {
                throw NagramSessionBackupError.invalidFile
            }
        }
        switch (backup.data.notificationEncryptionKeyId, backup.data.notificationEncryptionKey) {
        case (nil, nil):
            break
        case let (id?, key?):
            let digest = MTSha1(key)
            guard key.count == 256, digest.count >= 8, id == digest.suffix(8) else {
                throw NagramSessionBackupError.invalidFile
            }
        default:
            throw NagramSessionBackupError.invalidFile
        }
    }

    static func validateAuthorization(_ authorization: NagramExternalSessionAuthorization) throws {
        let validDatacenters = authorization.testingEnvironment ? 1 ... 3 : 1 ... 5
        guard validDatacenters.contains(Int(authorization.masterDatacenterId)), authorization.authKey.count == 256 else {
            throw NagramSessionBackupError.invalidFile
        }
        if let peerId = authorization.peerId, peerId <= 0 {
            throw NagramSessionBackupError.invalidFile
        }
    }
}

enum NagramSessionBackupCrypto {
    static let minimumPasswordLength = 6
    private static let rounds = 600_000

    static func encrypt(_ archive: NagramSessionArchive, password: String) throws -> String {
        guard password.count >= minimumPasswordLength else {
            throw NagramSessionBackupError.invalidPassword
        }
        try NagramSessionBackupValidator.validate(archive)
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
        let encoded = try JSONEncoder().encode(envelope).base64EncodedString()
        guard encoded.utf8.count <= NagramSessionBackupValidator.maximumArchiveFileSize else {
            throw NagramSessionBackupError.invalidFile
        }
        return encoded
    }

    static func decrypt(_ encoded: String, password: String) throws -> NagramSessionArchive {
        guard password.count >= minimumPasswordLength else {
            throw NagramSessionBackupError.invalidPassword
        }
        guard encoded.utf8.count <= NagramSessionBackupValidator.maximumArchiveFileSize,
              let envelopeData = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)),
              envelopeData.count <= NagramSessionBackupValidator.maximumArchiveFileSize,
              let envelope = try? JSONDecoder().decode(NagramEncryptedSessionEnvelope.self, from: envelopeData),
              envelope.version == 1,
              envelope.kdf == "PBKDF2-HMAC-SHA512",
              envelope.rounds == rounds,
              envelope.salt.count == 16,
              envelope.sealedBox.count >= 28,
              envelope.sealedBox.count <= NagramSessionBackupValidator.maximumArchiveFileSize else {
            throw NagramSessionBackupError.invalidFile
        }
        let plaintext: Data
        do {
            let key = try deriveKey(password: password, salt: envelope.salt, rounds: envelope.rounds)
            plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.sealedBox), using: key)
        } catch let error as NagramSessionBackupError {
            throw error
        } catch {
            throw NagramSessionBackupError.invalidPassword
        }
        do {
            let archive = try JSONDecoder().decode(NagramSessionArchive.self, from: plaintext)
            try NagramSessionBackupValidator.validate(archive)
            return archive
        } catch {
            throw NagramSessionBackupError.invalidFile
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
        try NagramSessionBackupValidator.validate(archive)
        let encoded = try JSONEncoder().encode(archive)
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: true
        ]
        let updateStatus = SecItemUpdate(base as CFDictionary, [
            kSecValueData: encoded,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked
        ] as CFDictionary)
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
        guard status == errSecSuccess, let data = result as? Data else {
            throw NagramSessionBackupError.keychain(status)
        }
        let archive = try JSONDecoder().decode(NagramSessionArchive.self, from: data)
        try NagramSessionBackupValidator.validate(archive)
        return archive
    }

    static func delete() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NagramSessionBackupError.keychain(status)
        }
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
            let archive = NagramSessionArchive(accounts: values)
            do {
                try NagramSessionBackupValidator.validate(archive)
                return .single(archive)
            } catch let error as NagramSessionBackupError {
                return .fail(error)
            } catch {
                return .fail(.invalidFile)
            }
        }
    }
}

private struct NagramInstalledSessions {
    let allIds: [AccountRecordId]
    let newIds: [AccountRecordId]
    let expectedNewPeerIds: [AccountRecordId: EnginePeer.Id]
    let targetId: AccountRecordId
}

func nagramRestoreSessionArchive(context: AccountContext, backups: [NagramSessionBackup]) -> Signal<[AccountRecordId], NagramSessionBackupError> {
    let archive = NagramSessionArchive(accounts: backups)
    do {
        try NagramSessionBackupValidator.validate(archive)
    } catch let error as NagramSessionBackupError {
        return .fail(error)
    } catch {
        return .fail(.invalidFile)
    }

    let orderedBackups = backups.enumerated().sorted { lhs, rhs in
        if lhs.element.sortOrder != rhs.element.sortOrder {
            return lhs.element.sortOrder < rhs.element.sortOrder
        }
        return lhs.offset < rhs.offset
    }.map(\.element)
    let pendingNewIds = Atomic<[AccountRecordId]>(value: [])
    let reachedTerminalState = Atomic<Bool>(value: false)

    func removeRecords(_ ids: [AccountRecordId]) -> Signal<Void, NoError> {
        guard !ids.isEmpty else {
            return .single(Void())
        }
        return context.sharedContext.accountManager.transaction { transaction -> Void in
            for id in ids {
                transaction.updateRecord(id, { _ in nil })
            }
        }
    }

    let install = context.sharedContext.accountManager.transaction { transaction -> Result<NagramInstalledSessions, NagramSessionBackupError> in
        let records = transaction.getRecords()
        var productionCount = 0
        for record in records {
            let isTest = record.attributes.contains(where: { attribute in
                if case let .environment(value) = attribute {
                    return value.environment == .test
                }
                return false
            })
            if !isTest {
                productionCount += 1
            }
        }

        var existingIds: [String: AccountRecordId] = [:]
        for record in records {
            var peerId: Int64?
            var testingEnvironment = false
            for attribute in record.attributes {
                switch attribute {
                case let .backupData(value):
                    peerId = value.data?.peerId
                case let .environment(value):
                    testingEnvironment = value.environment == .test
                default:
                    break
                }
            }
            if let peerId {
                existingIds["\(testingEnvironment).\(peerId)"] = record.id
            }
        }

        let newProductionCount = orderedBackups.filter { backup in
            !backup.testingEnvironment && existingIds["\(backup.testingEnvironment).\(backup.data.peerId)"] == nil
        }.count
        guard productionCount + newProductionCount <= maximumNumberOfAccounts else {
            return .failure(.capacityExceeded)
        }

        let maxSortOrder = records.compactMap { record -> Int32? in
            for attribute in record.attributes {
                if case let .sortOrder(value) = attribute {
                    return value.order
                }
            }
            return nil
        }.max() ?? -1
        let newAccountCount = orderedBackups.filter { backup in
            existingIds["\(backup.testingEnvironment).\(backup.data.peerId)"] == nil
        }.count
        guard Int64(maxSortOrder) + Int64(newAccountCount) <= Int64(Int32.max) else {
            return .failure(.capacityExceeded)
        }
        var nextSortOrder = Int64(maxSortOrder)
        var allIds: [AccountRecordId] = []
        var newIds: [AccountRecordId] = []
        var expectedNewPeerIds: [AccountRecordId: EnginePeer.Id] = [:]
        for backup in orderedBackups {
            let key = "\(backup.testingEnvironment).\(backup.data.peerId)"
            if let existingId = existingIds[key] {
                allIds.append(existingId)
                continue
            }
            nextSortOrder += 1
            let id = transaction.createRecord([
                .environment(AccountEnvironmentAttribute(environment: backup.testingEnvironment ? .test : .production)),
                .backupData(AccountBackupDataAttribute(data: backup.data)),
                .sortOrder(AccountSortOrderAttribute(order: Int32(nextSortOrder)))
            ])
            allIds.append(id)
            newIds.append(id)
            expectedNewPeerIds[id] = EnginePeer.Id(backup.data.peerId)
        }
        guard let firstId = allIds.first else {
            return .failure(.noBackup)
        }
        let targetIndex = orderedBackups.firstIndex(where: { $0.isPrimary }) ?? 0
        let targetId = allIds.indices.contains(targetIndex) ? allIds[targetIndex] : firstId
        _ = pendingNewIds.swap(newIds)
        return .success(NagramInstalledSessions(allIds: allIds, newIds: newIds, expectedNewPeerIds: expectedNewPeerIds, targetId: targetId))
    }
    |> castError(NagramSessionBackupError.self)
    |> mapToSignal { result -> Signal<[AccountRecordId], NagramSessionBackupError> in
        let installed: NagramInstalledSessions
        switch result {
        case let .success(value):
            installed = value
        case let .failure(error):
            return .fail(error)
        }

        let verified: Signal<Void, NagramSessionBackupError>
        if installed.newIds.isEmpty {
            verified = .single(Void())
        } else {
            verified = context.sharedContext.activeAccountsWithInfo
            |> filter { value in
                return installed.expectedNewPeerIds.allSatisfy { id, peerId in
                    value.accounts.contains(where: { $0.account.id == id && $0.peer.id == peerId })
                }
            }
            |> take(1)
            |> map { _ in Void() }
            |> castError(NagramSessionBackupError.self)
            |> timeout(60.0, queue: .mainQueue(), alternate: .fail(.verificationTimedOut))
        }
        return verified
        |> mapToSignal { _ -> Signal<[AccountRecordId], NagramSessionBackupError> in
            return context.sharedContext.accountManager.transaction { transaction -> Bool in
                guard transaction.getRecords().contains(where: { $0.id == installed.targetId }) else {
                    return false
                }
                transaction.setCurrentId(installed.targetId)
                return true
            }
            |> castError(NagramSessionBackupError.self)
            |> mapToSignal { success -> Signal<[AccountRecordId], NagramSessionBackupError> in
                guard success else {
                    return .fail(.verificationTimedOut)
                }
                _ = pendingNewIds.swap([])
                _ = reachedTerminalState.swap(true)
                return .single(installed.allIds)
            }
        }
    }
    |> `catch` { error -> Signal<[AccountRecordId], NagramSessionBackupError> in
        let ids = pendingNewIds.swap([])
        return removeRecords(ids)
        |> castError(NagramSessionBackupError.self)
        |> mapToSignal { _ -> Signal<[AccountRecordId], NagramSessionBackupError> in
            _ = reachedTerminalState.swap(true)
            return .fail(error)
        }
    }
    |> afterDisposed {
        if !reachedTerminalState.swap(true) {
            let ids = pendingNewIds.swap([])
            if !ids.isEmpty {
                let _ = removeRecords(ids).start()
            }
        }
    }

    return install
}
