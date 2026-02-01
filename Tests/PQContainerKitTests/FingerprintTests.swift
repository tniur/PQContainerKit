//
//  FingerprintTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("Fingerprint")
struct FingerprintTests {
    @Test("Fingerprint is 32 bytes and stable")
    func fingerprintBasics() throws {
        let pair = try PQContainerKit.MLKEM768.generateKeyPair()
        let fp1 = pair.publicKey.fingerprint
        let fp2 = pair.publicKey.fingerprint

        #expect(fp1.rawValue.count == PQContainerKit.Fingerprint.byteCount)
        #expect(fp1 == fp2)
    }

    @Test("Fingerprint consistent across export/import")
    func fingerprintConsistentAcrossImport() throws {
        let pair = try PQContainerKit.MLKEM768.generateKeyPair()
        let imported = try PQContainerKit.MLKEM768.PublicKey(rawRepresentation: pair.publicKey.rawRepresentation)
        #expect(imported.fingerprint == pair.publicKey.fingerprint)
    }

    @Test("Fingerprint raw initializer enforces 32 bytes")
    func fingerprintRawInitializer() {
        #expect(PQContainerKit.Fingerprint(rawValue: Data(repeating: 0, count: 31)) == nil)
        #expect(PQContainerKit.Fingerprint(rawValue: Data(repeating: 0, count: 32)) != nil)
        #expect(PQContainerKit.Fingerprint(rawValue: Data(repeating: 0, count: 33)) == nil)
    }
}
