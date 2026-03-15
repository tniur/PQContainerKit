//
//  ChunkCrypto.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 14.03.2026.
//

import CryptoKit
import Foundation

internal struct EncryptedChunk: Sendable {
    let ciphertext: Data
    let tag: Data
}

internal enum ChunkCrypto {
    static let baseNonceByteCount = AESGCM.nonceByteCount

    static func deriveChunkNonce(baseNonce: Data, chunkIndex: UInt64) -> Data {
        var nonce = [UInt8](baseNonce)
        var index = chunkIndex.littleEndian

        withUnsafeBytes(of: &index) { indexBytes in
            for i in 0 ..< 8 {
                nonce[nonce.count - 8 + i] ^= indexBytes[i]
            }
        }

        return Data(nonce)
    }

    static func makeChunkAAD(containerID: Data, chunkIndex: UInt64, chunkCount: UInt64) -> Data {
        var aad = Data(capacity: containerID.count + 16)
        aad.append(containerID)

        var indexLE = chunkIndex.littleEndian
        withUnsafeBytes(of: &indexLE) { aad.append(contentsOf: $0) }

        var countLE = chunkCount.littleEndian
        withUnsafeBytes(of: &countLE) { aad.append(contentsOf: $0) }

        return aad
    }

    static func encryptPayload(
        _ payload: Data,
        key: SymmetricKey,
        baseNonce: Data,
        chunkSize: Int,
        containerID: Data
    ) throws -> [EncryptedChunk] {
        guard !payload.isEmpty else {
            throw ContainerError.invalidFormat
        }

        let totalSize = payload.count
        let chunkCount = UInt64((totalSize + chunkSize - 1) / chunkSize)

        var chunks: [EncryptedChunk] = []
        chunks.reserveCapacity(Int(chunkCount))

        for i in 0 ..< chunkCount {
            let start = payload.startIndex + Int(i) * chunkSize
            let end = min(start + chunkSize, payload.endIndex)
            let chunkData = payload[start ..< end]

            let nonce = deriveChunkNonce(baseNonce: baseNonce, chunkIndex: i)
            let aad = makeChunkAAD(containerID: containerID, chunkIndex: i, chunkCount: chunkCount)

            let (ct, tag) = try AESGCM.seal(Data(chunkData), key: key, nonce: nonce, authenticating: aad)
            chunks.append(EncryptedChunk(ciphertext: ct, tag: tag))
        }

        return chunks
    }

    static func decryptPayload(
        chunks: [EncryptedChunk],
        key: SymmetricKey,
        baseNonce: Data,
        containerID: Data
    ) throws -> Data {
        guard !chunks.isEmpty else {
            throw ContainerError.invalidFormat
        }

        let chunkCount = UInt64(chunks.count)
        var result = Data()

        for (i, chunk) in chunks.enumerated() {
            let nonce = deriveChunkNonce(baseNonce: baseNonce, chunkIndex: UInt64(i))
            let aad = makeChunkAAD(containerID: containerID, chunkIndex: UInt64(i), chunkCount: chunkCount)

            let plaintext = try AESGCM.open(
                ciphertext: chunk.ciphertext,
                tag: chunk.tag,
                key: key,
                nonce: nonce,
                authenticating: aad
            )
            result.append(plaintext)
        }

        return result
    }
}
