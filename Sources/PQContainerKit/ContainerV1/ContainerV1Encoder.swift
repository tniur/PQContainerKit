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
        guard Int(header.recipientsCount) == recipients.count else {
            throw ContainerError.invalidFormat
        }

        guard recipients.count >= 1,
              recipients.count <= ContainerV1Constants.maxRecipients
        else {
            throw ContainerError.limitsExceeded
        }

        guard UInt64(cipherParts.ciphertext.count) <= ContainerV1Constants.maxCiphertextSize else {
            throw ContainerError.limitsExceeded
        }

        for entry in recipients {
            guard !entry.kemCiphertext.isEmpty,
                  entry.kemCiphertext.count <= ContainerV1Constants.maxKEMCiphertextSize
            else {
                throw ContainerError.limitsExceeded
            }

            guard !entry.wrappedDEK.isEmpty,
                  entry.wrappedDEK.count <= ContainerV1Constants.maxWrappedDEKSize
            else {
                throw ContainerError.limitsExceeded
            }
        }

        let headerBytes = try encodeHeader(header)

        guard headerBytes.count <= ContainerV1Constants.maxHeaderSize else {
            throw ContainerError.limitsExceeded
        }

        var writer = BinaryWriter()

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
        writer.appendUInt64LE(UInt64(cipherParts.ciphertext.count))
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

        guard writer.data.count == ContainerV1Constants.headerFixedByteCount else {
            throw ContainerError.invalidFormat
        }

        return writer.data
    }
}
