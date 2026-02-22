//
//  ContainerV1Constants.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

/// Internal constants for container format v1.
///
/// Keep these limits close to the parser to enforce early validation and DoS resistance.
internal enum ContainerV1Constants {
    // MARK: - Magic / Version

    /// Magic bytes for v1 containers: ASCII `"PQCK"` (`0x50 0x51 0x43 0x4B`).
    static let magic: Data = .init([0x50, 0x51, 0x43, 0x4B])
    static let version: UInt16 = 1

    // MARK: - Header

    /// Fixed header byte size for v1:
    /// algId(2) + containerID(16) + recipientsCount(2) + flags(4) + reserved(16) = 40 bytes.
    static let headerFixedByteCount = 40

    /// Length-prefix upper bound for the header block.
    static let maxHeaderSize = 4096

    // MARK: - Recipients

    static let recipientKeyIdByteCount = 32
    static let maxRecipients = 100

    /// KEM ciphertext length upper bound (bytes).
    static let maxKEMCiphertextSize = 2048

    /// wrappedDEK length upper bound (bytes).
    static let maxWrappedDEKSize = 128

    // MARK: - Cipher parts

    static let ivByteCount = 12
    static let authTagByteCount = 16

    /// Ciphertext length upper bound (bytes) to reduce memory/CPU DoS risk.
    ///
    /// Note: file import already implies loading `Data` into memory, but we still limit what we accept.
    static let maxCiphertextSize: UInt64 = 512 * 1024 * 1024 // 512 MiB
}
