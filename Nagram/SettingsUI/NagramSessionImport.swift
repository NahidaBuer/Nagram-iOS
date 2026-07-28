import Foundation
import MtProtoKit
import TelegramCore
import sqlcipher

// MARK: NAGRAM — Strict, read-only import of third-party MTProto sessions.
enum NagramExternalSessionSource: Equatable {
    case pyrogramFile
    case pyrogramString
    case telethonFile
    case telethonString

    var label: String {
        switch self {
        case .pyrogramFile:
            return "Pyrogram SQLite"
        case .pyrogramString:
            return "Pyrogram StringSession"
        case .telethonFile:
            return "Telethon SQLite"
        case .telethonString:
            return "Telethon StringSession"
        }
    }
}

struct NagramExternalSessionAuthorization: Equatable {
    let source: NagramExternalSessionSource
    let testingEnvironment: Bool
    let masterDatacenterId: Int32
    let authKey: Data
    let peerId: Int64?

    func makeBackup(peerId suppliedPeerId: Int64? = nil) throws -> NagramSessionBackup {
        guard let peerId = self.peerId ?? suppliedPeerId, peerId > 0 else {
            throw NagramSessionBackupError.missingPeerId
        }
        let backup = NagramSessionBackup(
            testingEnvironment: self.testingEnvironment,
            sortOrder: 0,
            isPrimary: true,
            label: self.source.label,
            data: AccountBackupData(
                masterDatacenterId: self.masterDatacenterId,
                peerId: peerId,
                masterDatacenterKey: self.authKey,
                masterDatacenterKeyId: nagramAuthKeyId(self.authKey),
                notificationEncryptionKeyId: nil,
                notificationEncryptionKey: nil,
                additionalDatacenterKeys: [:]
            )
        )
        try NagramSessionBackupValidator.validate(backup)
        return backup
    }
}

enum NagramSessionStringParser {
    static func parse(_ value: String) throws -> NagramExternalSessionAuthorization {
        let string = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !string.isEmpty, string.utf8.count <= 4096 else {
            throw NagramSessionBackupError.invalidFile
        }
        if string.first == "1", let telethon = try? self.parseTelethon(string) {
            return telethon
        }
        return try self.parsePyrogram(string)
    }

    private static func parsePyrogram(_ string: String) throws -> NagramExternalSessionAuthorization {
        guard let data = decodeBase64Url(string) else {
            throw NagramSessionBackupError.invalidFile
        }
        var reader = NagramBigEndianReader(data: data)
        let dcId: UInt8
        let testingEnvironment: Bool
        let authKey: Data
        let userId: UInt64
        let isBot: Bool
        switch data.count {
        case 271:
            dcId = try reader.readUInt8()
            _ = try reader.readUInt32()
            testingEnvironment = try reader.readBool()
            authKey = try reader.readData(count: 256)
            userId = try reader.readUInt64()
            isBot = try reader.readBool()
        case 263:
            dcId = try reader.readUInt8()
            testingEnvironment = try reader.readBool()
            authKey = try reader.readData(count: 256)
            userId = UInt64(try reader.readUInt32())
            isBot = try reader.readBool()
        case 267:
            dcId = try reader.readUInt8()
            testingEnvironment = try reader.readBool()
            authKey = try reader.readData(count: 256)
            userId = try reader.readUInt64()
            isBot = try reader.readBool()
        default:
            throw NagramSessionBackupError.unsupportedFormat
        }
        guard reader.isAtEnd, !isBot, userId > 0, userId <= UInt64(Int64.max) else {
            throw isBot ? NagramSessionBackupError.botSession : NagramSessionBackupError.invalidFile
        }
        let authorization = NagramExternalSessionAuthorization(
            source: .pyrogramString,
            testingEnvironment: testingEnvironment,
            masterDatacenterId: Int32(dcId),
            authKey: authKey,
            peerId: Int64(userId)
        )
        _ = try authorization.makeBackup()
        return authorization
    }

    private static func parseTelethon(_ string: String) throws -> NagramExternalSessionAuthorization {
        guard string.first == "1", let data = decodeBase64Url(String(string.dropFirst())), data.count == 263 || data.count == 275 else {
            throw NagramSessionBackupError.invalidFile
        }
        var reader = NagramBigEndianReader(data: data)
        let dcId = try reader.readUInt8()
        let address = try reader.readData(count: data.count == 263 ? 4 : 16)
        let port = try reader.readUInt16()
        let authKey = try reader.readData(count: 256)
        guard reader.isAtEnd, port > 0 else {
            throw NagramSessionBackupError.invalidFile
        }
        let testingEnvironment = telethonTestAddresses.contains(address)
        let authorization = NagramExternalSessionAuthorization(
            source: .telethonString,
            testingEnvironment: testingEnvironment,
            masterDatacenterId: Int32(dcId),
            authKey: authKey,
            peerId: nil
        )
        try NagramSessionBackupValidator.validateAuthorization(authorization)
        return authorization
    }
}

enum NagramSessionDatabaseParser {
    static let maximumFileSize = 128 * 1024 * 1024

    static func parse(_ url: URL) throws -> NagramExternalSessionAuthorization {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true, let fileSize = values.fileSize, fileSize > 0, fileSize <= self.maximumFileSize else {
            throw NagramSessionBackupError.invalidFile
        }
        let header = try Data(contentsOf: url, options: [.mappedIfSafe]).prefix(16)
        guard header == Data("SQLite format 3\0".utf8) else {
            throw NagramSessionBackupError.invalidFile
        }
        let database = try NagramReadOnlyDatabase(url: url)
        if let version = try? database.singleInt32("SELECT number FROM version") {
            guard (3 ... 7).contains(version) else {
                throw NagramSessionBackupError.unsupportedFormat
            }
            let row = try database.singleRow("SELECT dc_id, test_mode, auth_key, user_id, is_bot FROM sessions")
            guard row.count == 5,
                  let dcId = row[0].int64,
                  let testingEnvironment = row[1].int64,
                  let authKey = row[2].data,
                  let userId = row[3].int64,
                  let isBot = row[4].int64,
                  testingEnvironment == 0 || testingEnvironment == 1,
                  isBot == 0 || isBot == 1 else {
                throw NagramSessionBackupError.invalidFile
            }
            guard isBot == 0 else {
                throw NagramSessionBackupError.botSession
            }
            let authorization = NagramExternalSessionAuthorization(
                source: .pyrogramFile,
                testingEnvironment: testingEnvironment != 0,
                masterDatacenterId: try checkedInt32(dcId),
                authKey: authKey,
                peerId: userId
            )
            _ = try authorization.makeBackup()
            return authorization
        }

        let version = try database.singleInt32("SELECT version FROM version")
        guard version == 7 || version == 8 else {
            throw NagramSessionBackupError.unsupportedFormat
        }
        let row = try database.singleRow("SELECT dc_id, server_address, port, auth_key FROM sessions")
        guard row.count == 4,
              let dcId = row[0].int64,
              let port = row[2].int64,
              let authKey = row[3].data,
              port > 0, port <= Int64(UInt16.max) else {
            throw NagramSessionBackupError.invalidFile
        }
        let address = row[1].string ?? ""
        let testingEnvironment = telethonTestAddressStrings.contains(address.lowercased())
        let authorization = NagramExternalSessionAuthorization(
            source: .telethonFile,
            testingEnvironment: testingEnvironment,
            masterDatacenterId: try checkedInt32(dcId),
            authKey: authKey,
            peerId: nil
        )
        try NagramSessionBackupValidator.validateAuthorization(authorization)
        return authorization
    }
}

func nagramAuthKeyId(_ key: Data) -> Int64 {
    let digest = MTSha1(key)
    guard digest.count >= 8 else {
        return 0
    }
    var result: Int64 = 0
    _ = withUnsafeMutableBytes(of: &result) { destination in
        digest.copyBytes(to: destination, from: digest.count - 8 ..< digest.count)
    }
    return result
}

private let telethonTestAddresses: Set<Data> = [
    Data([149, 154, 175, 10]),
    Data([149, 154, 167, 40]),
    Data([149, 154, 175, 117]),
    Data([0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e]),
    Data([0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0xf0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e]),
    Data([0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0xf0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e])
]

private let telethonTestAddressStrings: Set<String> = [
    "149.154.175.10",
    "149.154.167.40",
    "149.154.175.117",
    "2001:b28:f23d:f001::e",
    "2001:67c:4e8:f002::e",
    "2001:b28:f23d:f003::e"
]

private func checkedInt32(_ value: Int64) throws -> Int32 {
    guard value >= Int64(Int32.min), value <= Int64(Int32.max) else {
        throw NagramSessionBackupError.invalidFile
    }
    return Int32(value)
}

private func decodeBase64Url(_ value: String) -> Data? {
    var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
    return Data(base64Encoded: base64)
}

private struct NagramBigEndianReader {
    let data: Data
    private(set) var offset: Int = 0

    var isAtEnd: Bool {
        return self.offset == self.data.count
    }

    mutating func readUInt8() throws -> UInt8 {
        guard self.offset < self.data.count else {
            throw NagramSessionBackupError.invalidFile
        }
        defer { self.offset += 1 }
        return self.data[self.offset]
    }

    mutating func readBool() throws -> Bool {
        let value = try self.readUInt8()
        guard value == 0 || value == 1 else {
            throw NagramSessionBackupError.invalidFile
        }
        return value == 1
    }

    mutating func readUInt16() throws -> UInt16 {
        let value = try self.readData(count: 2)
        return value.reduce(0) { ($0 << 8) | UInt16($1) }
    }

    mutating func readUInt32() throws -> UInt32 {
        let value = try self.readData(count: 4)
        return value.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func readUInt64() throws -> UInt64 {
        let value = try self.readData(count: 8)
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func readData(count: Int) throws -> Data {
        guard count >= 0, self.offset <= self.data.count - count else {
            throw NagramSessionBackupError.invalidFile
        }
        defer { self.offset += count }
        return self.data.subdata(in: self.offset ..< self.offset + count)
    }
}

private enum NagramSQLiteValue {
    case integer(Int64)
    case blob(Data)
    case text(String)
    case null

    var int64: Int64? {
        if case let .integer(value) = self {
            return value
        }
        return nil
    }

    var data: Data? {
        if case let .blob(value) = self {
            return value
        }
        return nil
    }

    var string: String? {
        if case let .text(value) = self {
            return value
        }
        return nil
    }
}

private final class NagramReadOnlyDatabase {
    private var handle: OpaquePointer?

    init(url: URL) throws {
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOFOLLOW
        guard sqlite3_open_v2(url.path, &self.handle, flags, nil) == SQLITE_OK, self.handle != nil else {
            if self.handle != nil {
                sqlite3_close(self.handle)
            }
            throw NagramSessionBackupError.invalidFile
        }
        guard sqlite3_exec(self.handle, "PRAGMA query_only = ON", nil, nil, nil) == SQLITE_OK else {
            throw NagramSessionBackupError.invalidFile
        }
    }

    deinit {
        sqlite3_close(self.handle)
    }

    func singleInt32(_ sql: String) throws -> Int32 {
        let row = try self.singleRow(sql)
        guard row.count == 1, let value = row[0].int64 else {
            throw NagramSessionBackupError.invalidFile
        }
        return try checkedInt32(value)
    }

    func singleRow(_ sql: String) throws -> [NagramSQLiteValue] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(self.handle, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NagramSessionBackupError.invalidFile
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw NagramSessionBackupError.invalidFile
        }
        var result: [NagramSQLiteValue] = []
        for index in 0 ..< sqlite3_column_count(statement) {
            switch sqlite3_column_type(statement, index) {
            case SQLITE_INTEGER:
                result.append(.integer(sqlite3_column_int64(statement, index)))
            case SQLITE_BLOB:
                let count = Int(sqlite3_column_bytes(statement, index))
                if count == 0 {
                    result.append(.blob(Data()))
                } else if let bytes = sqlite3_column_blob(statement, index) {
                    result.append(.blob(Data(bytes: bytes, count: count)))
                } else {
                    throw NagramSessionBackupError.invalidFile
                }
            case SQLITE_TEXT:
                guard let bytes = sqlite3_column_text(statement, index) else {
                    throw NagramSessionBackupError.invalidFile
                }
                result.append(.text(String(cString: bytes)))
            case SQLITE_NULL:
                result.append(.null)
            default:
                throw NagramSessionBackupError.invalidFile
            }
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw NagramSessionBackupError.invalidFile
        }
        return result
    }
}
