//
//  MLKEM768+KEM.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit
import Foundation

internal extension MLKEM768 {
    static func encapsulate(to recipientPublicKey: PublicKey) throws -> KEMResult {
        do {
            let pk = try recipientPublicKey.cryptoKitKey()
            let (ss, ctRaw) = try CryptoKitMLKEM768Adapter.encapsulate(to: pk)

            let ct = try Ciphertext(rawRepresentation: ctRaw)
            return KEMResult(sharedSecret: ss, ciphertext: ct)
        } catch let сontainerKitError as ContainerKitError {
            throw сontainerKitError
        } catch {
            throw ContainerKitError.kemEncapsulationFailed
        }
    }

    static func decapsulate(privateKey: PrivateKey, ciphertext: Ciphertext) throws -> SymmetricKey {
        do {
            return try CryptoKitMLKEM768Adapter.decapsulate(
                using: privateKey.cryptoKitKey,
                encapsulated: ciphertext.rawRepresentation
            )
        } catch {
            throw ContainerKitError.kemDecapsulationFailed
        }
    }
}
