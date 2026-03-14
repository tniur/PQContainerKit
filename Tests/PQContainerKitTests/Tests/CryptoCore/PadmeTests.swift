//
//  PadmeTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 14.03.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("CryptoCore: Padme")
struct PadmeTests {
    @Test("paddedLength is deterministic")
    func paddedLengthIsDeterministic() {
        for size in [0, 1, 2, 5, 100, 1000, 10000, 100_000, 1_000_000] {
            #expect(Padme.paddedLength(size) == Padme.paddedLength(size))
        }
    }

    @Test("paddedLength is always >= input")
    func paddedLengthIsAlwaysGreaterOrEqual() {
        for size in 0 ... 1024 {
            #expect(Padme.paddedLength(size) >= size)
        }
    }

    @Test("paddedLength overhead is at most 12%")
    func paddedLengthOverheadAtMost12Percent() {
        for exp in 3 ..< 20 {
            let size = 1 << exp
            for offset in [0, 1, size / 3, size / 2, size - 1] {
                let input = size + offset
                let padded = Padme.paddedLength(input)
                let overhead = Double(padded - input) / Double(input)
                #expect(overhead <= 0.12, "Overhead \(overhead) > 12% for input \(input)")
            }
        }
    }

    @Test("pad/unpad round-trip preserves plaintext")
    func padUnpadRoundTrip() throws {
        let testCases: [Data] = [
            Data("hello world".utf8),
            Data("x".utf8),
            Data(repeating: 0xAB, count: 1000),
            Data(repeating: 0xFF, count: 10000)
        ]

        for plaintext in testCases {
            let padded = try Padme.pad(plaintext)
            let recovered = try Padme.unpad(padded)
            #expect(recovered == plaintext)
        }
    }

    @Test("pad/unpad round-trip for empty plaintext")
    func padUnpadEmptyPlaintext() throws {
        let padded = try Padme.pad(Data())
        let recovered = try Padme.unpad(padded)
        #expect(recovered == Data())
    }

    @Test("padded size equals paddedLength of payload")
    func paddedSizeMatchesPaddedLength() throws {
        for size in [0, 1, 5, 100, 1000, 10000] {
            let plaintext = Data(repeating: 0x42, count: size)
            let padded = try Padme.pad(plaintext)
            let expectedLength = Padme.paddedLength(8 + size)
            #expect(padded.count == expectedLength)
        }
    }

    @Test("unpad rejects payload shorter than 8 bytes")
    func unpadRejectsTooShort() {
        #expect(throws: ContainerError.invalidFormat) {
            try Padme.unpad(Data(repeating: 0x00, count: 7))
        }
    }

    @Test("unpad rejects invalid original length")
    func unpadRejectsInvalidLength() {
        var payload = Data(count: 16)
        var lengthLE = UInt64(100).littleEndian
        withUnsafeBytes(of: &lengthLE) { payload.replaceSubrange(0 ..< 8, with: $0) }

        #expect(throws: ContainerError.invalidFormat) {
            try Padme.unpad(payload)
        }
    }

    @Test("Close plaintext sizes produce identical ciphertext sizes")
    func closePlaintextSizesProduceIdenticalCiphertextSizes() throws {
        let owner = try XWing.generateKeyPair()

        let plaintext1 = Data(repeating: 0x41, count: 847)
        let plaintext2 = Data(repeating: 0x42, count: 851)

        let container1 = try ContainerV1.createContainer(
            plaintext: plaintext1,
            recipients: [],
            owner: owner.publicKey
        )

        let container2 = try ContainerV1.createContainer(
            plaintext: plaintext2,
            recipients: [],
            owner: owner.publicKey
        )

        #expect(container1.count == container2.count)
    }
}
