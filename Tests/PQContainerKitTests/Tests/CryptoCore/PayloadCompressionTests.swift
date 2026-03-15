//
//  PayloadCompressionTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 15.03.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("CryptoCore: PayloadCompression")
struct PayloadCompressionTests {
    @Test("compress/decompress round-trip preserves data")
    func roundTrip() throws {
        let original = Data("hello world, this is a test of compression".utf8)
        let compressed = try PayloadCompression.compress(original)
        let decompressed = try PayloadCompression.decompress(compressed)
        #expect(decompressed == original)
    }

    @Test("tryCompress returns compressed=true for compressible data")
    func tryCompressCompressible() throws {
        let original = Data(repeating: 0x41, count: 10000)
        let (result, compressed) = try PayloadCompression.tryCompress(original)
        #expect(compressed)
        #expect(result.count < original.count)

        let decompressed = try PayloadCompression.decompress(result)
        #expect(decompressed == original)
    }

    @Test("tryCompress returns compressed=false for incompressible data")
    func tryCompressIncompressible() throws {
        var random = Data(count: 256)
        let status = random.withUnsafeMutableBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, 256, base)
        }
        #expect(status == errSecSuccess)

        let (result, compressed) = try PayloadCompression.tryCompress(random)
        #expect(!compressed)
        #expect(result == random)
    }

    @Test("empty data passes through unchanged")
    func emptyData() throws {
        let (result, compressed) = try PayloadCompression.tryCompress(Data())
        #expect(!compressed)
        #expect(result.isEmpty)
    }

    @Test("compressed container round-trip via ContainerV1")
    func containerRoundTrip() throws {
        let owner = try XWing.generateKeyPair()
        let plaintext = Data(repeating: 0x42, count: 5000)

        let containerData = try ContainerV1.createContainer(
            plaintext: plaintext,
            recipients: [],
            owner: owner.publicKey
        )

        let opened = try ContainerV1.openContainer(
            containerData: containerData,
            myPrivateKey: owner.privateKey,
            myPublicKey: owner.publicKey
        )

        #expect(opened == plaintext)
    }

    @Test("compressed container is smaller than uncompressed payload")
    func containerSizeReduced() throws {
        let owner = try XWing.generateKeyPair()
        let plaintext = Data(repeating: 0x41, count: 50000)

        let containerData = try ContainerV1.createContainer(
            plaintext: plaintext,
            recipients: [],
            owner: owner.publicKey
        )

        let info = try ContainerV1.inspectContainer(containerData)
        #expect(info.header.flags & 0x0001 != 0)
        #expect(containerData.count < plaintext.count)
    }
}
