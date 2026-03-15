//
//  ContainerV1Constants.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

internal enum ContainerV1Constants {
    // MARK: - Magic / Version

    static let magic: Data = .init([0x50, 0x51, 0x43, 0x4B])
    static let version: UInt16 = 1

    // MARK: - Header

    static let headerFixedByteCount: Int = 2 + ContainerID.byteCount + 2 + 4 + ContainerHeader.reservedByteCount
    static let maxHeaderSize: Int = 4096

    // MARK: - Recipients

    static let recipientKeyIdByteCount: Int = Fingerprint.byteCount
    static let maxRecipients: Int = 100
    static let maxKEMCiphertextSize: Int = 2048
    static let maxWrappedDEKSize: Int = 128

    // MARK: - Flags

    static let flagZlibCompression: UInt32 = 0x0001

    // MARK: - Chunked cipher

    static let defaultChunkSize: Int = 1_048_576
    static let maxChunkSize: UInt32 = 64 * 1024 * 1024
}
