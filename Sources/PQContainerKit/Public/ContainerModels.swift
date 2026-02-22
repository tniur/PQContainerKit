//
//  ContainerModels.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

/// Unique identifier of a container (16 bytes).
///
/// In the v1 format it is stored as raw 16 bytes (UUID-like), and is used
/// as part of KDF context/AAD binding.
public struct ContainerID: Hashable, Sendable {
    /// Byte length of a container identifier.
    public static let byteCount = 16

    private let uuid: UUID

    /// Raw bytes (always 16 bytes).
    public var rawValue: Data {
        var uuid = uuid.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
    }

    /// Creates a container identifier from raw bytes.
    ///
    /// Returns `nil` if the byte length is not 16.
    public init?(rawValue: Data) {
        guard rawValue.count == Self.byteCount else { return nil }

        var uuidT: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &uuidT) { dst in
            _ = rawValue.copyBytes(to: dst)
        }
        uuid = UUID(uuid: uuidT)
    }

    /// Generates a random `ContainerID`.
    public static func random() -> ContainerID {
        ContainerID(uuid: UUID())
    }

    private init(uuid: UUID) {
        self.uuid = uuid
    }
}

/// Identifier of the algorithm suite used by a container format.
///
/// v1 defines a single suite: `{ ML-KEM-768, HKDF-SHA-256, AES-256-GCM }`.
public struct AlgId: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// v1 default algorithm suite.
    public static let mlkem768HkdfSha256Aes256Gcm = AlgId(rawValue: 0x0001)
}

/// Container header (v1).
///
/// Header is stored as a fixed-size structure in v1 (currently 40 bytes):
/// `algId(2) | containerID(16) | recipientsCount(2) | flags(4) | reserved(16)`.
public struct ContainerHeader: Hashable, Sendable {
    public static let reservedByteCount = 16

    public let algId: AlgId
    public let containerID: ContainerID
    public let recipientsCount: UInt16
    public let flags: UInt32
    public let reserved: Data

    /// Creates a header.
    ///
    /// - Throws: `ContainerError.invalidFormat` if `reserved` length is invalid.
    public init(
        algId: AlgId,
        containerID: ContainerID,
        recipientsCount: UInt16,
        flags: UInt32 = 0,
        reserved: Data = Data(repeating: 0x00, count: Self.reservedByteCount)
    ) throws {
        guard reserved.count == Self.reservedByteCount else {
            throw ContainerError.invalidFormat
        }

        self.algId = algId
        self.containerID = containerID
        self.recipientsCount = recipientsCount
        self.flags = flags
        self.reserved = reserved
    }
}

/// Recipient entry (v1).
///
/// Represents a single recipient's access record: recipientKeyId + KEM ciphertext + wrapped DEK.
public struct RecipientEntry: Hashable, Sendable {
    public let recipientKeyId: Fingerprint
    public let kemCiphertext: Data
    public let wrappedDEK: Data

    public init(recipientKeyId: Fingerprint, kemCiphertext: Data, wrappedDEK: Data) {
        self.recipientKeyId = recipientKeyId
        self.kemCiphertext = kemCiphertext
        self.wrappedDEK = wrappedDEK
    }
}

/// Cipher components of a container: IV/nonce + ciphertext + auth tag.
public struct CipherParts: Hashable, Sendable {
    public static let ivByteCount = 12
    public static let authTagByteCount = 16

    public let iv: Data
    public let ciphertext: Data
    public let authTag: Data

    /// Creates cipher parts.
    ///
    /// - Throws: `ContainerError.invalidFormat` if IV/tag lengths are not valid.
    public init(iv: Data, ciphertext: Data, authTag: Data) throws {
        guard iv.count == Self.ivByteCount else { throw ContainerError.invalidFormat }
        guard authTag.count == Self.authTagByteCount else { throw ContainerError.invalidFormat }
        self.iv = iv
        self.ciphertext = ciphertext
        self.authTag = authTag
    }
}
