//
//  ContainerModels.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

public struct ContainerID: Hashable, Sendable {
    public static let byteCount = 16

    private let uuid: UUID

    public var rawValue: Data {
        var bytes = uuid.uuid
        return withUnsafeBytes(of: &bytes) { Data($0) }
    }

    public init?(rawValue: Data) {
        guard rawValue.count == Self.byteCount else {
            return nil
        }

        var raw: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &raw) { dst in
            _ = rawValue.copyBytes(to: dst)
        }

        uuid = UUID(uuid: raw)
    }

    public static func random() -> ContainerID {
        ContainerID(uuid: UUID())
    }

    private init(uuid: UUID) {
        self.uuid = uuid
    }
}

public struct AlgId: RawRepresentable, Hashable, Sendable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let mlkem768HkdfSha256Aes256Gcm = AlgId(rawValue: 0x0001)
}

public struct ContainerHeader: Hashable, Sendable {
    public static let reservedByteCount = 16

    public let algId: AlgId
    public let containerID: ContainerID
    public let recipientsCount: UInt16

    public let flags: UInt32
    public let reserved: Data

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

public struct CipherParts: Hashable, Sendable {
    public static let ivByteCount = 12
    public static let authTagByteCount = 16

    public let iv: Data
    public let ciphertext: Data
    public let authTag: Data

    public init(iv: Data, ciphertext: Data, authTag: Data) throws {
        guard iv.count == Self.ivByteCount else {
            throw ContainerError.invalidFormat
        }

        guard authTag.count == Self.authTagByteCount else {
            throw ContainerError.invalidFormat
        }

        self.iv = iv
        self.ciphertext = ciphertext
        self.authTag = authTag
    }
}
