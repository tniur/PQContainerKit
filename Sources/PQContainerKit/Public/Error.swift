//
//  Error.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

public extension PQContainerKit {
    /// Public error type for PQContainerKit.
    ///
    /// Intentionally does not expose low-level cryptographic failure details.
    enum Error: Swift.Error, Equatable, Sendable {
        /// The provided Base64 string is not valid Base64.
        case invalidBase64

        /// The provided key bytes are not a valid representation for the expected key type.
        case invalidKeyRepresentation

        /// Key generation failed (platform API error).
        case keyGenerationFailed
    }
}
