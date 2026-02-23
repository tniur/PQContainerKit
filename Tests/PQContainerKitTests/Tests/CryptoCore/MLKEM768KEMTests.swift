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

@Suite("CryptoCore: ML-KEM-768 (KEM)")
struct MLKEM768KEMTests {
    @Test("Encapsulate/decapsulate yields identical shared secret")
    func kemCorrectnessUT04() throws {
        let pair = try MLKEM768.generateKeyPair()

        let kem = try MLKEM768.encapsulate(to: pair.publicKey)
        let ss2 = try MLKEM768.decapsulate(
            privateKey: pair.privateKey,
            ciphertext: kem.ciphertext
        )

        #expect(TestByteUtils.data(of: kem.sharedSecret) == TestByteUtils.data(of: ss2))
    }

    @Test("Decapsulate with different private key yields different shared secret")
    func kemIsolationUT05() throws {
        let keyPair1 = try MLKEM768.generateKeyPair()
        let keyPair2 = try MLKEM768.generateKeyPair()

        let kem = try MLKEM768.encapsulate(to: keyPair1.publicKey)
        let ssWrong = try MLKEM768.decapsulate(
            privateKey: keyPair2.privateKey,
            ciphertext: kem.ciphertext
        )

        #expect(TestByteUtils.data(of: kem.sharedSecret) != TestByteUtils.data(of: ssWrong))
    }

    @Test("Ciphertext initializer rejects invalid length")
    func ciphertextValidation() {
        #expect(throws: PQContainerKit.ContainerKitError.invalidCiphertextRepresentation) {
            _ = try MLKEM768.Ciphertext(rawRepresentation: Data(repeating: 0, count: 1))
        }
    }
}
