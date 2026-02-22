//
//  ContainerV1Encoder.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

/// Binary encoder for container format v1.
///
/// Layout:
/// `magic(4) | version(u16) | headerLength(u32) | headerBytes | recipients[] | iv(12) | ciphertextLength(u64) |
/// ciphertext | authTag(16)`.
///
/// The encoder enforces format limits (recipient counts, field sizes) to avoid producing
/// containers that would be rejected by `validate/decode`.
internal enum ContainerV1Encoder {
    /// Encodes a v1 container from parsed components.
    ///
    /// - Parameters:
    ///   - header: Parsed header model.
    ///   - recipients: Recipient entries, must match `header.recipientsCount`.
    ///   - cipherParts: AES-GCM parts (iv/ciphertext/tag).
    ///
    /// - Throws: `ContainerError` if inputs violate v1 constraints.
    internal static func encode(
        header: ContainerHeader,
        recipients: [RecipientEntry],
        cipherParts: CipherParts
    ) throws -> Data {
        try validateHeaderRecipientsConsistency(header: header, recipients: recipients)
        try validateRecipientsLimits(recipients)
        let headerBytes = try encodeHeader(header)
        try validateHeaderLength(headerBytes.count)

        let recipientsBytesTotal = try totalRecipientsBytes(recipients)
        try validateCiphertextSize(cipherParts.ciphertext.count)

        let capacity = estimatedCapacity(
            headerBytesCount: headerBytes.count,
            recipientsBytesTotal: recipientsBytesTotal,
            ciphertextCount: cipherParts.ciphertext.count
        )

        var writer = BinaryWriter(capacity: capacity)

        writePreamble(into: &writer)
        try writeHeaderBlock(headerBytes, into: &writer)
        writeRecipients(recipients, into: &writer)
        writeCipherParts(cipherParts, into: &writer)

        return writer.data
    }

    /// Encodes a v1 fixed-size header (40 bytes).
    private static func encodeHeader(_ header: ContainerHeader) throws -> Data {
        var writer = BinaryWriter(capacity: ContainerV1Constants.headerFixedByteCount)

        writer.appendUInt16LE(header.algId.rawValue)
        writer.append(header.containerID.rawValue)
        writer.appendUInt16LE(header.recipientsCount)
        writer.appendUInt32LE(header.flags)
        writer.append(header.reserved)

        let bytes = writer.data
        guard bytes.count == ContainerV1Constants.headerFixedByteCount else {
            throw ContainerError.invalidFormat
        }

        return bytes
    }

    /// Validates that header recipientsCount matches the actual recipients array length.
    private static func validateHeaderRecipientsConsistency(
        header: ContainerHeader,
        recipients: [RecipientEntry]
    ) throws {
        guard Int(header.recipientsCount) == recipients.count else {
            throw ContainerError.invalidFormat
        }
    }

    /// Validates the recipients count is within v1 DoS limits.
    private static func validateRecipientsLimits(_ recipients: [RecipientEntry]) throws {
        guard recipients.count >= 1, recipients.count <= ContainerV1Constants.maxRecipients else {
            throw ContainerError.limitsExceeded
        }
    }

    /// Validates header length against v1 maximum header size.
    private static func validateHeaderLength(_ headerBytesCount: Int) throws {
        guard headerBytesCount <= ContainerV1Constants.maxHeaderSize else {
            throw ContainerError.limitsExceeded
        }

        guard headerBytesCount <= Int(UInt32.max) else {
            throw ContainerError.limitsExceeded
        }
    }

    /// Computes the total serialized size of recipient entries, validating per-entry limits.
    private static func totalRecipientsBytes(_ recipients: [RecipientEntry]) throws -> Int {
        var total = 0

        total += recipients.count * ContainerV1Constants.recipientKeyIdByteCount
        total += recipients.count * 2
        total += recipients.count * 2

        for entry in recipients {
            let kemCount = entry.kemCiphertext.count
            let wrappedCount = entry.wrappedDEK.count

            guard kemCount > 0,
                  kemCount <= ContainerV1Constants.maxKEMCiphertextSize,
                  kemCount <= Int(UInt16.max)
            else {
                throw ContainerError.limitsExceeded
            }

            guard wrappedCount > 0,
                  wrappedCount <= ContainerV1Constants.maxWrappedDEKSize,
                  wrappedCount <= Int(UInt16.max)
            else {
                throw ContainerError.limitsExceeded
            }

            total += kemCount + wrappedCount
        }

        return total
    }

    /// Validates ciphertext size against v1 DoS limits.
    private static func validateCiphertextSize(_ ciphertextCount: Int) throws {
        guard UInt64(ciphertextCount) <= ContainerV1Constants.maxCiphertextSize else {
            throw ContainerError.limitsExceeded
        }
    }

    /// Estimates output capacity to reduce `Data` reallocations.
    private static func estimatedCapacity(
        headerBytesCount: Int,
        recipientsBytesTotal: Int,
        ciphertextCount: Int
    ) -> Int {
        let fixedOverhead =
            ContainerV1Constants.magic.count +
            2 +
            4 +
            headerBytesCount +
            ContainerV1Constants.ivByteCount +
            8 +
            ContainerV1Constants.authTagByteCount

        return fixedOverhead + recipientsBytesTotal + ciphertextCount
    }

    /// Writes magic and version.
    private static func writePreamble(into writer: inout BinaryWriter) {
        writer.append(ContainerV1Constants.magic)
        writer.appendUInt16LE(ContainerV1Constants.version)
    }

    /// Writes header length prefix and header bytes.
    private static func writeHeaderBlock(_ headerBytes: Data, into writer: inout BinaryWriter) throws {
        guard headerBytes.count <= Int(UInt32.max) else { throw ContainerError.limitsExceeded }
        writer.appendUInt32LE(UInt32(headerBytes.count))
        writer.append(headerBytes)
    }

    /// Writes recipient entries in v1 layout.
    private static func writeRecipients(_ recipients: [RecipientEntry], into writer: inout BinaryWriter) {
        for entry in recipients {
            writer.append(entry.recipientKeyId.rawValue)
            writer.appendUInt16LE(UInt16(entry.kemCiphertext.count))
            writer.append(entry.kemCiphertext)
            writer.appendUInt16LE(UInt16(entry.wrappedDEK.count))
            writer.append(entry.wrappedDEK)
        }
    }

    /// Writes AES-GCM parts in v1 layout.
    private static func writeCipherParts(_ cipherParts: CipherParts, into writer: inout BinaryWriter) {
        writer.append(cipherParts.iv)
        writer.appendUInt64LE(UInt64(cipherParts.ciphertext.count))
        writer.append(cipherParts.ciphertext)
        writer.append(cipherParts.authTag)
    }
}
