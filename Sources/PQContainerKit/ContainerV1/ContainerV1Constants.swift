//
//  ContainerV1Constants.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

internal enum ContainerV1Constants {
    static let magic: Data = .init([0x50, 0x51, 0x43, 0x4B])
    static let version: UInt16 = 1

    static let headerFixedByteCount = 40
    static let maxHeaderSize = 4096

    static let recipientKeyIdByteCount = 32
    static let maxRecipients = 100

    static let maxKEMCiphertextSize = 2048
    static let maxWrappedDEKSize = 128

    static let ivByteCount = 12
    static let authTagByteCount = 16

    static let maxCiphertextSize: UInt64 = 512 * 1024 * 1024
}
