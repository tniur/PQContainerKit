//
//  Fingerprint.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

import CryptoKit
import Foundation

public extension PQContainerKit {
    struct Fingerprint: Hashable, Sendable {
        public static let byteCount = 32
        public let rawValue: Data

        public init?(rawValue: Data) {
            guard rawValue.count == Self.byteCount else { return nil }
            self.rawValue = rawValue
        }

        init(sha256Digest: SHA256.Digest) {
            rawValue = Data(sha256Digest)
        }

        public var hexStringGrouped: String {
            let hex = rawValue.map { String(format: "%02x", $0) }.joined()
            return stride(from: 0, to: hex.count, by: 8).map { idx in
                let start = hex.index(hex.startIndex, offsetBy: idx)
                let end = hex.index(start, offsetBy: min(8, hex.count - idx))
                return String(hex[start ..< end])
            }.joined(separator: " ")
        }
    }
}

public extension PQContainerKit.Fingerprint {
    static func fromPublicKeyRaw(_ publicKeyRaw: Data) -> PQContainerKit.Fingerprint {
        PQContainerKit.Fingerprint(sha256Digest: SHA256.hash(data: publicKeyRaw))
    }
}
