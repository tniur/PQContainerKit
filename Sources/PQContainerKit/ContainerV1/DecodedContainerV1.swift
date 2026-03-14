//
//  DecodedContainerV1.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

internal struct ChunkedCipherData: Sendable {
    let baseNonce: Data
    let chunkSize: UInt32
    let totalPayloadSize: UInt64
    let chunks: [EncryptedChunk]
}

internal struct DecodedContainerV1: Sendable {
    internal let header: ContainerHeader
    internal let recipients: [RecipientEntry]
    internal let cipherData: ChunkedCipherData
}
