//
//  ContainerV1Encoder.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

internal enum ContainerV1Encoder {
    internal static func encode(
        header: ContainerHeader,
        recipients: [RecipientEntry],
        cipherParts: CipherParts
    ) throws -> Data {
        guard header.algId == .mlkem768HkdfSha256Aes256Gcm else {
            throw ContainerError.invalidFormat
        }

        guard Int(header.recipientsCount) == recipients.count else {
            throw ContainerError.invalidFormat
        }

        guard recipients.count >= 1, recipients.count <= ContainerV1Constants.maxRecipients else {
            throw ContainerError.limitsExceeded
        }

        let headerBytes = try encodeHeader(header)

        guard headerBytes.count >= ContainerV1Constants.headerFixedByteCount else {
            throw ContainerError.invalidFormat
        }

        guard headerBytes.count <= ContainerV1Constants.maxHeaderSize else {
            throw ContainerError.limitsExceeded
        }

        guard headerBytes.count <= Int(UInt32.max) else {
            throw ContainerError.limitsExceeded
        }

        let recipientsBytesTotal = try validateAndEstimateRecipientsBytes(recipients)

        let ciphertextCount = cipherParts.ciphertext.count
        guard UInt64(ciphertextCount) <= ContainerV1Constants.maxCiphertextSize else {
            throw ContainerError.limitsExceeded
        }

        let capacity = estimateCapacity(
            headerBytesCount: headerBytes.count,
            recipientsBytesCount: recipientsBytesTotal,
            ciphertextCount: ciphertextCount
        )

        var writer = BinaryWriter(capacity: capacity)

        writer.append(ContainerV1Constants.magic)
        writer.appendUInt16LE(ContainerV1Constants.version)

        writer.appendUInt32LE(UInt32(headerBytes.count))
        writer.append(headerBytes)

        for entry in recipients {
            writer.append(entry.recipientKeyId.rawValue)

            writer.appendUInt16LE(UInt16(entry.kemCiphertext.count))
            writer.append(entry.kemCiphertext)

            writer.appendUInt16LE(UInt16(entry.wrappedDEK.count))
            writer.append(entry.wrappedDEK)
        }

        writer.append(cipherParts.iv)
        writer.appendUInt64LE(UInt64(ciphertextCount))
        writer.append(cipherParts.ciphertext)
        writer.append(cipherParts.authTag)

        return writer.data
    }

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

    private static func validateAndEstimateRecipientsBytes(_ recipients: [RecipientEntry]) throws -> Int {
        var total = 0

        total += recipients.count * ContainerV1Constants.recipientKeyIdByteCount
        total += recipients.count * 2
        total += recipients.count * 2

        for entry in recipients {
            let kemCount = entry.kemCiphertext.count
            if kemCount == 0 { throw ContainerError.invalidFormat }
            if kemCount > ContainerV1Constants.maxKEMCiphertextSize { throw ContainerError.limitsExceeded }
            if kemCount > Int(UInt16.max) { throw ContainerError.limitsExceeded }

            let wrappedCount = entry.wrappedDEK.count
            if wrappedCount == 0 { throw ContainerError.invalidFormat }
            if wrappedCount > ContainerV1Constants.maxWrappedDEKSize { throw ContainerError.limitsExceeded }
            if wrappedCount > Int(UInt16.max) { throw ContainerError.limitsExceeded }

            total += kemCount + wrappedCount
        }

        return total
    }

    private static func estimateCapacity(
        headerBytesCount: Int,
        recipientsBytesCount: Int,
        ciphertextCount: Int
    ) -> Int {
        let fixed =
            ContainerV1Constants.magic.count +
            2 +
            4 +
            headerBytesCount +
            ContainerV1Constants.ivByteCount +
            8 +
            ContainerV1Constants.authTagByteCount

        return fixed + recipientsBytesCount + ciphertextCount
    }
}
