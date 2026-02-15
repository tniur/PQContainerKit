//
//  MLKEM768KeysTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("MLKEM768 keys")
struct MLKEM768KeysTests {
    @Test("KeyPair generation returns non-empty public key bytes")
    func keyPairGeneration() throws {
        let pair = try MLKEM768.generateKeyPair()
        #expect(!pair.publicKey.rawRepresentation.isEmpty)
    }

    @Test("PublicKey Base64 round-trip")
    func publicKeyBase64RoundTrip() throws {
        let pair = try MLKEM768.generateKeyPair()
        let exported = pair.publicKey.base64
        let imported = try MLKEM768.PublicKey(base64: exported)

        #expect(imported.rawRepresentation == pair.publicKey.rawRepresentation)
        #expect(imported.fingerprint == pair.publicKey.fingerprint)
    }

    @Test("Invalid Base64 throws")
    func invalidBase64Throws() {
        #expect(throws: PQContainerKit.Error.invalidBase64) {
            _ = try MLKEM768.PublicKey(base64: "not base64!!!")
        }
    }

    @Test("Valid Base64 but invalid key bytes throws invalidKeyRepresentation")
    func validBase64ButInvalidKeyBytes() {
        do {
            _ = try MLKEM768.PublicKey(base64: "AA==")
            #expect(Bool(false), "Expected invalidKeyRepresentation, but init succeeded")
        } catch let error as PQContainerKit.Error {
            #expect(error == .invalidKeyRepresentation)
        } catch {
            #expect(Bool(false), "Unexpected error type: \(error)")
        }
    }
}
