//
//  MLKEM768KEMTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation
@testable import PQContainerKit
import Testing

@Suite("MLKEM768 KEM")
struct MLKEM768KEMTests {
    private func bytes(of key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    @Test("UT-04: Encaps/Decaps produces identical shared secrets")
    func kemCorrectnessUT04() throws {
        let pair = try MLKEM768.generateKeyPair()

        let kem = try MLKEM768.encapsulate(to: pair.publicKey)
        let ss2 = try MLKEM768.decapsulate(privateKey: pair.privateKey, ciphertext: kem.ciphertext)

        #expect(bytes(of: kem.sharedSecret) == bytes(of: ss2))
    }

    @Test("UT-05: Decaps with a different private key yields a different shared secret")
    func kemIsolationUT05() throws {
        let keyPair1 = try MLKEM768.generateKeyPair()
        let keyPair2 = try MLKEM768.generateKeyPair()

        let kem = try MLKEM768.encapsulate(to: keyPair1.publicKey)
        let ssWrong = try MLKEM768.decapsulate(privateKey: keyPair2.privateKey, ciphertext: kem.ciphertext)

        #expect(bytes(of: kem.sharedSecret) != bytes(of: ssWrong))
    }

    @Test("Ciphertext validation rejects invalid byte length")
    func ciphertextValidation() {
        #expect(throws: PQContainerKit.ContainerKitError.invalidCiphertextRepresentation) {
            _ = try MLKEM768.Ciphertext(rawRepresentation: Data(repeating: 0, count: 1))
        }
    }
}
