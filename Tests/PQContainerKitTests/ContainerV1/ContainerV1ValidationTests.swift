//
//  ContainerV1ValidationTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 23.02.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("Container v1: validation")
struct ContainerV1ValidationTests {
    @Test("Rejects unsupported container version")
    func invalidVersionUT07() {
        var data = Data()
        data.append(Data("PQCK".utf8))
        data.append(contentsOf: UInt16(999).littleEndianBytes)

        #expect(throws: ContainerError.unsupportedVersion) {
            _ = try ContainerV1Validator.validate(containerData: data)
        }
    }

    @Test("Rejects recipientsCount above allowed limit")
    func limitsExceededUT08() {
        let headerBytes = makeHeader(recipientsCount: 10000)

        var data = Data()
        data.append(Data("PQCK".utf8))
        data.append(contentsOf: UInt16(1).littleEndianBytes)
        data.append(contentsOf: UInt32(headerBytes.count).littleEndianBytes)
        data.append(headerBytes)

        #expect(throws: ContainerError.limitsExceeded) {
            _ = try ContainerV1Validator.validate(containerData: data)
        }
    }

    private func makeHeader(recipientsCount: UInt16) -> Data {
        var writer = BinaryWriter(capacity: ContainerV1Constants.headerFixedByteCount)

        writer.appendUInt16LE(AlgId.mlkem768HkdfSha256Aes256Gcm.rawValue)
        writer.append(Data(repeating: 0x00, count: ContainerID.byteCount))
        writer.appendUInt16LE(recipientsCount)
        writer.appendUInt32LE(0)
        writer.append(Data(repeating: 0x00, count: ContainerHeader.reservedByteCount))

        return writer.data
    }
}

private extension FixedWidthInteger {
    var littleEndianBytes: [UInt8] {
        withUnsafeBytes(of: littleEndian) { Array($0) }
    }
}
