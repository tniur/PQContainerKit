//
//  MLKEM768+KEM.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation

extension MLKEM768 {
    static func encapsulate(to recipientPublicKey: PublicKey) throws -> KEMResult {
        do {
            let pk = try recipientPublicKey.cryptoKitKey()
            let result = try pk.encapsulate()
            let ct = try Ciphertext(rawRepresentation: result.encapsulated)
            return KEMResult(sharedSecret: result.sharedSecret, ciphertext: ct)
        } catch let containerKitError as ContainerKitError {
            throw containerKitError
        } catch {
            throw ContainerKitError.kemEncapsulationFailed
        }
    }

    static func decapsulate(privateKey: PrivateKey, ciphertext: Ciphertext) throws -> SymmetricKey {
        do {
            return try privateKey.cryptoKitKey.decapsulate(ciphertext.rawRepresentation)
        } catch {
            throw ContainerKitError.kemDecapsulationFailed
        }
    }
}
