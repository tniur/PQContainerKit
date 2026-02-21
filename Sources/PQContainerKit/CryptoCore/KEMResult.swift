//
//  KEMResult.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 21.02.2026.
//

import CryptoKit

struct KEMResult: Sendable {
    let sharedSecret: SymmetricKey
    let ciphertext: MLKEM768.Ciphertext
}
