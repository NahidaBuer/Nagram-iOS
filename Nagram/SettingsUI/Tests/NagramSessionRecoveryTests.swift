import Foundation
import TelegramCore
import XCTest
import sqlcipher
@testable import NagramSettingsUI

final class NagramSessionRecoveryTests: XCTestCase {
    func testSixCharacterPasswordRoundTrip() throws {
        let archive = NagramSessionArchive(accounts: [try self.makeAuthorization(peerId: 123).makeBackup()])
        let encoded = try NagramSessionBackupCrypto.encrypt(archive, password: "123456")
        let decoded = try NagramSessionBackupCrypto.decrypt(encoded, password: "123456")
        XCTAssertEqual(decoded.accounts.count, 1)
        XCTAssertEqual(decoded.accounts[0].data.peerId, 123)
        XCTAssertThrowsError(try NagramSessionBackupCrypto.encrypt(archive, password: "12345"))
        XCTAssertThrowsError(try NagramSessionBackupCrypto.decrypt(encoded, password: "12345"))
        XCTAssertThrowsError(try NagramSessionBackupCrypto.decrypt(encoded, password: "654321"))
    }

    func testPyrogramCurrentSessionString() throws {
        var data = Data([2])
        data.appendBigEndian(UInt32(2040))
        data.append(0)
        data.append(Data(repeating: 0x41, count: 256))
        data.appendBigEndian(UInt64(9_876_543_210))
        data.append(0)
        let parsed = try NagramSessionStringParser.parse(data.base64UrlString(removePadding: true))
        XCTAssertEqual(parsed.source, .pyrogramString)
        XCTAssertEqual(parsed.masterDatacenterId, 2)
        XCTAssertEqual(parsed.peerId, 9_876_543_210)
        XCTAssertFalse(parsed.testingEnvironment)
    }

    func testPyrogramLegacySessionStrings() throws {
        var legacy32 = Data([1, 1])
        legacy32.append(Data(repeating: 0x42, count: 256))
        legacy32.appendBigEndian(UInt32(123_456))
        legacy32.append(0)
        let parsed32 = try NagramSessionStringParser.parse(legacy32.base64UrlString(removePadding: true))
        XCTAssertEqual(parsed32.peerId, 123_456)
        XCTAssertTrue(parsed32.testingEnvironment)

        var legacy64 = Data([5, 0])
        legacy64.append(Data(repeating: 0x43, count: 256))
        legacy64.appendBigEndian(UInt64(5_000_000_000))
        legacy64.append(0)
        let parsed64 = try NagramSessionStringParser.parse(legacy64.base64UrlString(removePadding: true))
        XCTAssertEqual(parsed64.peerId, 5_000_000_000)
        XCTAssertFalse(parsed64.testingEnvironment)
    }

    func testPyrogramBotSessionIsRejected() throws {
        var data = Data([2])
        data.appendBigEndian(UInt32(2040))
        data.append(0)
        data.append(Data(repeating: 0x44, count: 256))
        data.appendBigEndian(UInt64(123))
        data.append(1)
        XCTAssertThrowsError(try NagramSessionStringParser.parse(data.base64UrlString(removePadding: true))) { error in
            guard case NagramSessionBackupError.botSession = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testTelethonSessionStringRequiresPeerId() throws {
        var data = Data([2, 149, 154, 167, 40])
        data.appendBigEndian(UInt16(443))
        data.append(Data(repeating: 0x45, count: 256))
        let parsed = try NagramSessionStringParser.parse("1" + data.base64UrlString(removePadding: false))
        XCTAssertEqual(parsed.source, .telethonString)
        XCTAssertNil(parsed.peerId)
        XCTAssertTrue(parsed.testingEnvironment)
        XCTAssertThrowsError(try parsed.makeBackup())
        XCTAssertEqual(try parsed.makeBackup(peerId: 777).data.peerId, 777)
    }

    func testArchiveRejectsForgedAuthKeyIdAndDuplicates() throws {
        let valid = try self.makeAuthorization(peerId: 123).makeBackup()
        let forged = NagramSessionBackup(
            testingEnvironment: false,
            sortOrder: 0,
            isPrimary: true,
            label: "forged",
            data: AccountBackupData(
                masterDatacenterId: 2,
                peerId: 123,
                masterDatacenterKey: Data(repeating: 0x46, count: 256),
                masterDatacenterKeyId: 0,
                notificationEncryptionKeyId: nil,
                notificationEncryptionKey: nil,
                additionalDatacenterKeys: [:]
            )
        )
        XCTAssertThrowsError(try NagramSessionBackupValidator.validate(forged))
        XCTAssertThrowsError(try NagramSessionBackupValidator.validate(NagramSessionArchive(accounts: [valid, valid])))
    }

    func testPyrogramSQLite() throws {
        let url = self.temporaryDatabaseUrl()
        defer { try? FileManager.default.removeItem(at: url) }
        let key = Data(repeating: 0x47, count: 256)
        try self.createDatabase(url: url, sql: """
        CREATE TABLE version (number INTEGER PRIMARY KEY);
        INSERT INTO version VALUES (7);
        CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, test_mode INTEGER, auth_key BLOB, user_id INTEGER, is_bot INTEGER);
        INSERT INTO sessions VALUES (4, 0, X'\(key.hexString)', 24680, 0);
        """)
        let parsed = try NagramSessionDatabaseParser.parse(url)
        XCTAssertEqual(parsed.source, .pyrogramFile)
        XCTAssertEqual(parsed.peerId, 24680)
        XCTAssertEqual(parsed.masterDatacenterId, 4)
    }

    func testTelethonSQLite() throws {
        let url = self.temporaryDatabaseUrl()
        defer { try? FileManager.default.removeItem(at: url) }
        let key = Data(repeating: 0x48, count: 256)
        try self.createDatabase(url: url, sql: """
        CREATE TABLE version (version INTEGER PRIMARY KEY);
        INSERT INTO version VALUES (8);
        CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, server_address TEXT, port INTEGER, auth_key BLOB, takeout_id INTEGER, tmp_auth_key BLOB);
        INSERT INTO sessions VALUES (3, '149.154.175.100', 443, X'\(key.hexString)', NULL, X'');
        """)
        let parsed = try NagramSessionDatabaseParser.parse(url)
        XCTAssertEqual(parsed.source, .telethonFile)
        XCTAssertNil(parsed.peerId)
        XCTAssertEqual(parsed.masterDatacenterId, 3)
        XCTAssertFalse(parsed.testingEnvironment)
    }

    func testTelethonProductionPort80IsNotTestEnvironment() throws {
        let url = self.temporaryDatabaseUrl()
        defer { try? FileManager.default.removeItem(at: url) }
        let key = Data(repeating: 0x4a, count: 256)
        try self.createDatabase(url: url, sql: """
        CREATE TABLE version (version INTEGER PRIMARY KEY);
        INSERT INTO version VALUES (8);
        CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, server_address TEXT, port INTEGER, auth_key BLOB, takeout_id INTEGER, tmp_auth_key BLOB);
        INSERT INTO sessions VALUES (2, '149.154.167.50', 80, X'\(key.hexString)', NULL, X'');
        """)
        let parsed = try NagramSessionDatabaseParser.parse(url)
        XCTAssertFalse(parsed.testingEnvironment)
    }

    func testSQLiteRejectsMultipleSessionRows() throws {
        let url = self.temporaryDatabaseUrl()
        defer { try? FileManager.default.removeItem(at: url) }
        let key = Data(repeating: 0x49, count: 256)
        try self.createDatabase(url: url, sql: """
        CREATE TABLE version (number INTEGER PRIMARY KEY);
        INSERT INTO version VALUES (7);
        CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, test_mode INTEGER, auth_key BLOB, user_id INTEGER, is_bot INTEGER);
        INSERT INTO sessions VALUES (1, 0, X'\(key.hexString)', 1, 0);
        INSERT INTO sessions VALUES (2, 0, X'\(key.hexString)', 2, 0);
        """)
        XCTAssertThrowsError(try NagramSessionDatabaseParser.parse(url))
    }

    private func makeAuthorization(peerId: Int64) -> NagramExternalSessionAuthorization {
        return NagramExternalSessionAuthorization(
            source: .pyrogramString,
            testingEnvironment: false,
            masterDatacenterId: 2,
            authKey: Data(repeating: 0x40, count: 256),
            peerId: peerId
        )
    }

    private func temporaryDatabaseUrl() -> URL {
        return FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathExtension("session")
    }

    private func createDatabase(url: URL, sql: String) throws {
        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &database), SQLITE_OK)
        guard let database else {
            throw NagramSessionBackupError.invalidFile
        }
        defer { sqlite3_close(database) }
        var errorMessage: UnsafeMutablePointer<CChar>?
        let result = sqlite3_exec(database, sql, nil, nil, &errorMessage)
        if let errorMessage {
            sqlite3_free(errorMessage)
        }
        XCTAssertEqual(result, SQLITE_OK)
        if result != SQLITE_OK {
            throw NagramSessionBackupError.invalidFile
        }
    }
}

private extension Data {
    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var value = value.bigEndian
        Swift.withUnsafeBytes(of: &value) { self.append(contentsOf: $0) }
    }

    func base64UrlString(removePadding: Bool) -> String {
        var value = self.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        if removePadding {
            value = value.replacingOccurrences(of: "=", with: "")
        }
        return value
    }

    var hexString: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}
