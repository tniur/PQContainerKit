//
//  XWing+KEM.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 11.03.2026.
//

import CryptoKit
import Foundation

internal extension XWing {
    static func encapsulate(to recipientPublicKey: PublicKey) throws -> KEMResult {
        do {
            let pk = try recipientPublicKey.cryptoKitKey()

            let (ss, ctRaw) = try CryptoKitXWingAdapter.encapsulate(to: pk)
            let ct = try Ciphertext(rawRepresentation: ctRaw)

            return KEMResult(sharedSecret: ss, ciphertext: ct)
        } catch let containerKitError as ContainerKitError {
            throw containerKitError
        } catch {
            throw ContainerKitError.kemEncapsulationFailed
        }
    }

    static func decapsulate(privateKey: PrivateKey, ciphertext: Ciphertext) throws -> SymmetricKey {
        do {
            return try CryptoKitXWingAdapter.decapsulate(
                using: privateKey.cryptoKitKey,
                encapsulated: ciphertext.rawRepresentation
            )
        } catch {
            throw ContainerKitError.kemDecapsulationFailed
        }
    }
}
