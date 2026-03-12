//
//  XWingKeysTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 12.03.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("Keys: X-Wing")
struct XWingKeysTests {
    @Test("GenerateKeyPair produces non-empty public key representation")
    func keyPairGeneration() throws {
        let pair = try XWing.generateKeyPair()
        #expect(!pair.publicKey.rawRepresentation.isEmpty)
    }

    @Test("Public key Base64 export/import round-trip")
    func publicKeyBase64RoundTrip() throws {
        let pair = try XWing.generateKeyPair()
        let exported = pair.publicKey.base64
        let imported = try XWing.PublicKey(base64: exported)

        #expect(imported.rawRepresentation == pair.publicKey.rawRepresentation)
        #expect(imported.fingerprint == pair.publicKey.fingerprint)
    }

    @Test("Public key init(base64:) rejects invalid Base64")
    func invalidBase64Throws() {
        #expect(throws: PQContainerKit.ContainerKitError.invalidBase64) {
            _ = try XWing.PublicKey(base64: "not base64!!!")
        }
    }

    @Test("Public key init(base64:) rejects invalid key bytes")
    func validBase64ButInvalidKeyBytes() {
        do {
            _ = try XWing.PublicKey(base64: "AA==")
            #expect(Bool(false), "Expected invalidKeyRepresentation, but init succeeded")
        } catch let error as PQContainerKit.ContainerKitError {
            #expect(error == .invalidKeyRepresentation)
        } catch {
            #expect(Bool(false), "Unexpected error type: \(error)")
        }
    }

    @Test("Ciphertext byteCount matches X-Wing specification")
    func ciphertextByteCount() {
        #expect(XWing.Ciphertext.byteCount == 1120)
    }
}
