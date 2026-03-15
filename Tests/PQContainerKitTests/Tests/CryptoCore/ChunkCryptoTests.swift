//
//  ChunkCryptoTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 14.03.2026.
//

import CryptoKit
import Foundation
@testable import PQContainerKit
import Testing

@Suite("CryptoCore: ChunkCrypto")
struct ChunkCryptoTests {
    @Test("deriveChunkNonce produces unique nonces for different indices")
    func uniqueNonces() {
        let baseNonce = Data(repeating: 0xAA, count: 12)

        let nonce0 = ChunkCrypto.deriveChunkNonce(baseNonce: baseNonce, chunkIndex: 0)
        let nonce1 = ChunkCrypto.deriveChunkNonce(baseNonce: baseNonce, chunkIndex: 1)
        let nonce2 = ChunkCrypto.deriveChunkNonce(baseNonce: baseNonce, chunkIndex: 2)

        #expect(nonce0 != nonce1)
        #expect(nonce1 != nonce2)
        #expect(nonce0 != nonce2)
    }

    @Test("deriveChunkNonce with index 0 returns baseNonce")
    func nonceIndexZero() {
        let baseNonce = Data(repeating: 0xBB, count: 12)
        let nonce = ChunkCrypto.deriveChunkNonce(baseNonce: baseNonce, chunkIndex: 0)
        #expect(nonce == baseNonce)
    }

    @Test("makeChunkAAD produces correct layout")
    func aadLayout() {
        let containerID = Data(repeating: 0x01, count: 16)
        let aad = ChunkCrypto.makeChunkAAD(containerID: containerID, chunkIndex: 3, chunkCount: 10)

        #expect(aad.count == 32)
        #expect(aad.prefix(16) == containerID)
    }

    @Test("encrypt/decrypt round-trip preserves payload")
    func roundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Data(repeating: 0xCC, count: 12)
        let containerID = Data(repeating: 0x42, count: 16)
        let payload = Data(repeating: 0xAB, count: 3000)

        let chunks = try ChunkCrypto.encryptPayload(
            payload,
            key: key,
            baseNonce: baseNonce,
            chunkSize: 1024,
            containerID: containerID
        )

        #expect(chunks.count == 3)

        let decrypted = try ChunkCrypto.decryptPayload(
            chunks: chunks,
            key: key,
            baseNonce: baseNonce,
            containerID: containerID
        )

        #expect(decrypted == payload)
    }

    @Test("single chunk for small payload")
    func singleChunk() throws {
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Data(repeating: 0x11, count: 12)
        let containerID = Data(repeating: 0x22, count: 16)
        let payload = Data("hello".utf8)

        let chunks = try ChunkCrypto.encryptPayload(
            payload,
            key: key,
            baseNonce: baseNonce,
            chunkSize: 1_048_576,
            containerID: containerID
        )

        #expect(chunks.count == 1)

        let decrypted = try ChunkCrypto.decryptPayload(
            chunks: chunks,
            key: key,
            baseNonce: baseNonce,
            containerID: containerID
        )

        #expect(decrypted == payload)
    }

    @Test("tampered chunk ciphertext fails decryption")
    func tamperedChunkFails() throws {
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Data(repeating: 0xDD, count: 12)
        let containerID = Data(repeating: 0x33, count: 16)
        let payload = Data(repeating: 0xFF, count: 2048)

        var chunks = try ChunkCrypto.encryptPayload(
            payload,
            key: key,
            baseNonce: baseNonce,
            chunkSize: 1024,
            containerID: containerID
        )

        var tamperedCT = [UInt8](chunks[0].ciphertext)
        tamperedCT[0] ^= 0x01
        chunks[0] = EncryptedChunk(ciphertext: Data(tamperedCT), tag: chunks[0].tag)

        #expect(throws: (any Error).self) {
            _ = try ChunkCrypto.decryptPayload(
                chunks: chunks,
                key: key,
                baseNonce: baseNonce,
                containerID: containerID
            )
        }
    }

    @Test("reordered chunks fail decryption")
    func reorderedChunksFail() throws {
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Data(repeating: 0xEE, count: 12)
        let containerID = Data(repeating: 0x44, count: 16)
        let payload = Data(repeating: 0xAA, count: 2048)

        let chunks = try ChunkCrypto.encryptPayload(
            payload,
            key: key,
            baseNonce: baseNonce,
            chunkSize: 1024,
            containerID: containerID
        )

        let reordered = [chunks[1], chunks[0]]

        #expect(throws: (any Error).self) {
            _ = try ChunkCrypto.decryptPayload(
                chunks: reordered,
                key: key,
                baseNonce: baseNonce,
                containerID: containerID
            )
        }
    }

    @Test("truncated chunks fail decryption")
    func truncatedChunksFail() throws {
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Data(repeating: 0x77, count: 12)
        let containerID = Data(repeating: 0x55, count: 16)
        let payload = Data(repeating: 0xBB, count: 3072)

        let chunks = try ChunkCrypto.encryptPayload(
            payload,
            key: key,
            baseNonce: baseNonce,
            chunkSize: 1024,
            containerID: containerID
        )

        let truncated = Array(chunks.prefix(2))

        #expect(throws: (any Error).self) {
            _ = try ChunkCrypto.decryptPayload(
                chunks: truncated,
                key: key,
                baseNonce: baseNonce,
                containerID: containerID
            )
        }
    }
}
