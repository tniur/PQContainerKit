//
//  ContainerV1Decoder.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

/// Binary decoder for container format v1.
///
/// The decoder performs structural parsing and enforces bounds/limits.
/// It does not perform any cryptographic operations.
internal enum ContainerV1Decoder {
    /// Decodes a v1 container into parsed components.
    ///
    /// - Important: Trailing bytes after the auth tag are treated as `invalidFormat`.
    internal static func decode(_ data: Data) throws -> DecodedContainerV1 {
        var reader = try BinaryReader(data)

        try readAndValidateMagic(using: &reader)
        try readAndValidateVersion(using: &reader)

        let headerBytes = try readHeaderBlock(using: &reader)
        let header = try decodeHeader(from: headerBytes)

        let recipients = try readRecipients(count: Int(header.recipientsCount), using: &reader)
        let cipherParts = try readCipherParts(using: &reader)

        guard reader.remainingCount == 0 else {
            throw ContainerError.invalidFormat
        }

        return DecodedContainerV1(header: header, recipients: recipients, cipherParts: cipherParts)
    }

    /// Validates the magic prefix equals `"PQCK"`.
    private static func readAndValidateMagic(using reader: inout BinaryReader) throws {
        let magic = try reader.readBytes(count: ContainerV1Constants.magic.count)
        guard magic == ContainerV1Constants.magic else {
            throw ContainerError.invalidFormat
        }
    }

    /// Validates the container version equals v1.
    private static func readAndValidateVersion(using reader: inout BinaryReader) throws {
        let version = try reader.readUInt16LE()
        guard version == ContainerV1Constants.version else {
            throw ContainerError.unsupportedVersion
        }
    }

    /// Reads a length-prefixed header block and enforces v1 header bounds.
    private static func readHeaderBlock(using reader: inout BinaryReader) throws -> Data {
        let headerLength = try reader.readUInt32LE()

        guard headerLength > 0 else { throw ContainerError.invalidFormat }
        guard headerLength <= UInt32(ContainerV1Constants.maxHeaderSize) else { throw ContainerError.limitsExceeded }
        guard headerLength >= UInt32(ContainerV1Constants.headerFixedByteCount) else {
            throw ContainerError.invalidFormat
        }

        return try reader.readBytes(count: Int(headerLength))
    }

    /// Reads and validates recipient entries for the given count.
    private static func readRecipients(count: Int, using reader: inout BinaryReader) throws -> [RecipientEntry] {
        guard count >= 1, count <= ContainerV1Constants.maxRecipients else {
            throw ContainerError.limitsExceeded
        }

        var recipients: [RecipientEntry] = []
        recipients.reserveCapacity(count)

        for _ in 0 ..< count {
            let keyIdRaw = try reader.readBytes(count: ContainerV1Constants.recipientKeyIdByteCount)
            guard let keyId = Fingerprint(rawValue: keyIdRaw) else {
                throw ContainerError.invalidFormat
            }

            let kemLen = try reader.readUInt16LE()
            guard kemLen > 0 else { throw ContainerError.invalidFormat }
            guard kemLen <= UInt16(ContainerV1Constants.maxKEMCiphertextSize) else {
                throw ContainerError.limitsExceeded
            }

            let kemCiphertext = try reader.readBytes(count: Int(kemLen))

            let wrappedLen = try reader.readUInt16LE()
            guard wrappedLen > 0 else { throw ContainerError.invalidFormat }
            guard wrappedLen <= UInt16(ContainerV1Constants.maxWrappedDEKSize) else {
                throw ContainerError.limitsExceeded
            }

            let wrappedDEK = try reader.readBytes(count: Int(wrappedLen))

            recipients.append(
                RecipientEntry(
                    recipientKeyId: keyId,
                    kemCiphertext: kemCiphertext,
                    wrappedDEK: wrappedDEK
                )
            )
        }

        return recipients
    }

    /// Reads AES-GCM components (iv + ciphertextLength + ciphertext + authTag).
    private static func readCipherParts(using reader: inout BinaryReader) throws -> CipherParts {
        let iv = try reader.readBytes(count: ContainerV1Constants.ivByteCount)

        let ciphertextLength = try reader.readUInt64LE()
        guard ciphertextLength <= ContainerV1Constants.maxCiphertextSize else { throw ContainerError.limitsExceeded }
        guard ciphertextLength <= UInt64(Int.max) else { throw ContainerError.limitsExceeded }

        let ciphertext = try reader.readBytes(count: Int(ciphertextLength))
        let authTag = try reader.readBytes(count: ContainerV1Constants.authTagByteCount)

        return try CipherParts(iv: iv, ciphertext: ciphertext, authTag: authTag)
    }

    /// Decodes a v1 header.
    ///
    /// If `headerLength` is larger than the v1 fixed part, remaining bytes are ignored
    /// to allow forward-compatibility within v1.
    private static func decodeHeader(from headerBytes: Data) throws -> ContainerHeader {
        var headerReader = try BinaryReader(headerBytes)

        let algRaw = try headerReader.readUInt16LE()

        let containerIdBytes = try headerReader.readBytes(count: ContainerID.byteCount)
        guard let containerID = ContainerID(rawValue: containerIdBytes) else {
            throw ContainerError.invalidFormat
        }

        let recipientsCount = try headerReader.readUInt16LE()
        let flags = try headerReader.readUInt32LE()
        let reserved = try headerReader.readBytes(count: ContainerHeader.reservedByteCount)

        if headerReader.remainingCount > 0 {
            try headerReader.skip(count: headerReader.remainingCount)
        }

        return try ContainerHeader(
            algId: AlgId(rawValue: algRaw),
            containerID: containerID,
            recipientsCount: recipientsCount,
            flags: flags,
            reserved: reserved
        )
    }
}
