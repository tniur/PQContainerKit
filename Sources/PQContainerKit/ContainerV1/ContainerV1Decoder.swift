//
//  ContainerV1Decoder.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

internal enum ContainerV1Decoder {
    internal static func decode(_ data: Data) throws -> DecodedContainerV1 {
        var reader = try BinaryReader(data)

        let magic = try reader.readBytes(count: ContainerV1Constants.magic.count)
        guard magic == ContainerV1Constants.magic else {
            throw ContainerError.invalidFormat
        }

        let version = try reader.readUInt16LE()
        guard version == ContainerV1Constants.version else {
            throw ContainerError.unsupportedVersion
        }

        let headerLength = try readAndValidateHeaderLength(using: &reader)
        let header = try decodeHeader(from: reader.readBytes(count: Int(headerLength)))

        guard header.algId == .xwingHkdfSha256Aes256Gcm else {
            throw ContainerError.invalidFormat
        }

        guard header.recipientsCount >= 1,
              header.recipientsCount <= UInt16(ContainerV1Constants.maxRecipients)
        else {
            throw ContainerError.limitsExceeded
        }

        let recipients = try readRecipients(count: Int(header.recipientsCount), using: &reader)
        let cipherParts = try readCipherParts(using: &reader)

        guard reader.remainingCount == 0 else {
            throw ContainerError.invalidFormat
        }

        return DecodedContainerV1(
            header: header,
            recipients: recipients,
            cipherParts: cipherParts
        )
    }

    private static func readAndValidateHeaderLength(using reader: inout BinaryReader) throws -> UInt32 {
        let headerLength = try reader.readUInt32LE()

        guard headerLength > 0,
              headerLength >= UInt32(ContainerV1Constants.headerFixedByteCount)
        else {
            throw ContainerError.invalidFormat
        }

        guard headerLength <= UInt32(ContainerV1Constants.maxHeaderSize) else {
            throw ContainerError.limitsExceeded
        }

        return headerLength
    }

    private static func decodeHeader(from bytes: Data) throws -> ContainerHeader {
        var reader = try BinaryReader(bytes)

        let algRaw = try reader.readUInt16LE()
        let containerIdBytes = try reader.readBytes(count: ContainerID.byteCount)
        let recipientsCount = try reader.readUInt16LE()
        let flags = try reader.readUInt32LE()
        let reserved = try reader.readBytes(count: ContainerHeader.reservedByteCount)

        if reader.remainingCount > 0 {
            try reader.skip(count: reader.remainingCount)
        }

        guard let containerID = ContainerID(rawValue: containerIdBytes) else {
            throw ContainerError.invalidFormat
        }

        return try ContainerHeader(
            algId: AlgId(rawValue: algRaw),
            containerID: containerID,
            recipientsCount: recipientsCount,
            flags: flags,
            reserved: reserved
        )
    }

    private static func readRecipients(count: Int, using reader: inout BinaryReader) throws -> [RecipientEntry] {
        var recipients: [RecipientEntry] = []
        recipients.reserveCapacity(count)

        for _ in 0 ..< count {
            let keyIdRaw = try reader.readBytes(count: ContainerV1Constants.recipientKeyIdByteCount)

            guard let keyId = Fingerprint(rawValue: keyIdRaw) else {
                throw ContainerError.invalidFormat
            }

            let kemLen = try readNonZeroLimitedUInt16(
                using: &reader,
                max: ContainerV1Constants.maxKEMCiphertextSize
            )

            let kemCiphertext = try reader.readBytes(count: kemLen)

            let wrappedLen = try readNonZeroLimitedUInt16(
                using: &reader,
                max: ContainerV1Constants.maxWrappedDEKSize
            )

            let wrappedDEK = try reader.readBytes(count: wrappedLen)

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

    private static func readNonZeroLimitedUInt16(using reader: inout BinaryReader, max: Int) throws -> Int {
        let value = try Int(reader.readUInt16LE())

        if value == 0 {
            throw ContainerError.invalidFormat
        }

        if value > max {
            throw ContainerError.limitsExceeded
        }

        return value
    }

    private static func readCipherParts(using reader: inout BinaryReader) throws -> CipherParts {
        let iv = try reader.readBytes(count: ContainerV1Constants.ivByteCount)

        let ciphertextLength = try reader.readUInt64LE()

        guard ciphertextLength <= ContainerV1Constants.maxCiphertextSize,
              ciphertextLength <= UInt64(Int.max)
        else {
            throw ContainerError.limitsExceeded
        }

        let ciphertext = try reader.readBytes(count: Int(ciphertextLength))
        let authTag = try reader.readBytes(count: ContainerV1Constants.authTagByteCount)

        return try CipherParts(iv: iv, ciphertext: ciphertext, authTag: authTag)
    }
}
