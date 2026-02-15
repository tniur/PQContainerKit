//
//  Fingerprint.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

/// A public key fingerprint.
///
/// In this project a fingerprint is defined as `SHA-256(publicKeyRaw)` (32 bytes).
/// It is used for manual verification (Verified/Unverified) and as a stable identifier
/// for recipient lookup.
public struct Fingerprint: Hashable, Sendable {
    /// Size of the fingerprint in bytes (SHA-256 digest length).
    public static let byteCount = 32

    /// Raw fingerprint bytes (always 32 bytes).
    public let rawValue: Data

    /// Creates a fingerprint from raw bytes.
    ///
    /// Returns `nil` if the byte length is not 32.
    public init?(rawValue: Data) {
        guard rawValue.count == Self.byteCount else { return nil }
        self.rawValue = rawValue
    }

    init(sha256Digest: SHA256.Digest) {
        rawValue = Data(sha256Digest)
    }

    /// A human-friendly lowercase hex string grouped by 4 bytes.
    ///
    /// Useful for manual comparison via an independent channel.
    public var hexStringGrouped: String {
        let hex = rawValue.map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 8).map { idx in
            let start = hex.index(hex.startIndex, offsetBy: idx)
            let end = hex.index(start, offsetBy: min(8, hex.count - idx))
            return String(hex[start ..< end])
        }.joined(separator: " ")
    }
}

public extension Fingerprint {
    /// Computes a fingerprint for a public key.
    ///
    /// - Parameter publicKeyRaw: The raw public key bytes.
    /// - Returns: `SHA-256(publicKeyRaw)` as a `Fingerprint`.
    static func fromPublicKeyRaw(_ publicKeyRaw: Data) -> Fingerprint {
        Fingerprint(sha256Digest: SHA256.hash(data: publicKeyRaw))
    }
}
