//
//  ContainerV1Validator.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 23.02.2026.
//

import Foundation

internal enum ContainerV1Validator {
    internal static func inspect(containerData: Data) throws -> ContainerInfo {
        var reader = try BinaryReader(containerData)

        try validateMagicAndVersion(using: &reader)

        let header = try readAndValidateHeader(using: &reader)
        let keyIds = try readRecipientKeyIds(count: Int(header.recipientsCount), using: &reader)
        try validateChunkedCipherSection(using: &reader)

        guard reader.remainingCount == 0 else {
            throw ContainerError.invalidFormat
        }

        return ContainerInfo(header: header, recipientKeyIds: keyIds)
    }

    internal static func validate(containerData: Data) throws -> ContainerHeader {
        var reader = try BinaryReader(containerData)

        try validateMagicAndVersion(using: &reader)

        let header = try readAndValidateHeader(using: &reader)
        try validateRecipientsSection(count: Int(header.recipientsCount), using: &reader)
        try validateChunkedCipherSection(using: &reader)

        guard reader.remainingCount == 0 else {
            throw ContainerError.invalidFormat
        }

        return header
    }

    private static func validateMagicAndVersion(using reader: inout BinaryReader) throws {
        let magic = try reader.readBytes(count: ContainerV1Constants.magic.count)
        guard magic == ContainerV1Constants.magic else {
            throw ContainerError.invalidFormat
        }

        let version = try reader.readUInt16LE()
        guard version == ContainerV1Constants.version else {
            throw ContainerError.unsupportedVersion
        }
    }

    private static func readAndValidateHeader(using reader: inout BinaryReader) throws -> ContainerHeader {
        let headerLength = try readHeaderLength(using: &reader)
        let headerBytes = try reader.readBytes(count: Int(headerLength))

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

        let header = try ContainerHeader(
            algId: AlgId(rawValue: algRaw),
            containerID: containerID,
            recipientsCount: recipientsCount,
            flags: flags,
            reserved: reserved
        )

        guard header.algId == .xwingHkdfSha256Aes256Gcm else {
            throw ContainerError.invalidFormat
        }

        let count = Int(header.recipientsCount)
        guard count >= 1, count <= ContainerV1Constants.maxRecipients else {
            throw ContainerError.limitsExceeded
        }

        return header
    }

    private static func readHeaderLength(using reader: inout BinaryReader) throws -> UInt32 {
        let headerLength = try reader.readUInt32LE()

        guard headerLength > 0 else { throw ContainerError.invalidFormat }
        guard headerLength <= UInt32(ContainerV1Constants.maxHeaderSize) else { throw ContainerError.limitsExceeded }
        guard headerLength >= UInt32(ContainerV1Constants.headerFixedByteCount) else {
            throw ContainerError.invalidFormat
        }

        return headerLength
    }

    private static func readRecipientKeyIds(
        count: Int,
        using reader: inout BinaryReader
    ) throws -> [Fingerprint] {
        guard count >= 1, count <= ContainerV1Constants.maxRecipients else {
            throw ContainerError.limitsExceeded
        }

        var keyIds: [Fingerprint] = []
        keyIds.reserveCapacity(count)

        for _ in 0 ..< count {
            let keyIdBytes = try reader.readBytes(count: ContainerV1Constants.recipientKeyIdByteCount)
            guard let fingerprint = Fingerprint(rawValue: keyIdBytes) else {
                throw ContainerError.invalidFormat
            }
            keyIds.append(fingerprint)

            let kemLen = try readNonZeroLimitedUInt16(using: &reader, max: ContainerV1Constants.maxKEMCiphertextSize)
            try reader.skip(count: kemLen)

            let wrappedLen = try readNonZeroLimitedUInt16(using: &reader, max: ContainerV1Constants.maxWrappedDEKSize)
            try reader.skip(count: wrappedLen)
        }

        return keyIds
    }

    private static func validateRecipientsSection(count: Int, using reader: inout BinaryReader) throws {
        guard count >= 1, count <= ContainerV1Constants.maxRecipients else {
            throw ContainerError.limitsExceeded
        }

        for _ in 0 ..< count {
            try reader.skip(count: ContainerV1Constants.recipientKeyIdByteCount)

            let kemLen = try readNonZeroLimitedUInt16(using: &reader, max: ContainerV1Constants.maxKEMCiphertextSize)
            try reader.skip(count: kemLen)

            let wrappedLen = try readNonZeroLimitedUInt16(using: &reader, max: ContainerV1Constants.maxWrappedDEKSize)
            try reader.skip(count: wrappedLen)
        }
    }

    private static func validateChunkedCipherSection(using reader: inout BinaryReader) throws {
        try reader.skip(count: ChunkCrypto.baseNonceByteCount)

        let chunkSize = try reader.readUInt32LE()

        guard chunkSize > 0, chunkSize <= ContainerV1Constants.maxChunkSize else {
            throw ContainerError.limitsExceeded
        }

        let totalPayloadSize = try reader.readUInt64LE()

        guard totalPayloadSize <= UInt64(Int.max) else {
            throw ContainerError.limitsExceeded
        }

        let totalSize = Int(totalPayloadSize)
        let cs = Int(chunkSize)
        let chunkCount = totalSize > 0 ? (totalSize + cs - 1) / cs : 0

        guard chunkCount > 0 else {
            throw ContainerError.invalidFormat
        }

        for i in 0 ..< chunkCount {
            let isLast = i == chunkCount - 1
            let ctSize = isLast ? totalSize - i * cs : cs
            try reader.skip(count: ctSize + AESGCM.tagByteCount)
        }
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
}
