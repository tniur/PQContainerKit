//
//  BinaryCoding.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

/// A bounds-checked reader for little-endian binary formats.
internal struct BinaryReader {
    private let data: Data
    private(set) var offset: Int

    internal init(_ data: Data, offset: Int = 0) throws {
        guard offset >= 0, offset <= data.count else {
            throw ContainerError.invalidFormat
        }

        self.data = data
        self.offset = offset
    }

    internal var remainingCount: Int {
        data.count - offset
    }

    internal mutating func readBytes(count: Int) throws -> Data {
        guard count >= 0 else { throw ContainerError.invalidFormat }
        guard count <= remainingCount else { throw ContainerError.invalidFormat }

        let range = offset ..< (offset + count)
        offset += count

        return data.subdata(in: range)
    }

    internal mutating func readUInt16LE() throws -> UInt16 {
        guard remainingCount >= 2 else { throw ContainerError.invalidFormat }

        let b0 = UInt16(data[offset])
        let b1 = UInt16(data[offset + 1]) << 8
        offset += 2

        return b0 | b1
    }

    internal mutating func readUInt32LE() throws -> UInt32 {
        guard remainingCount >= 4 else { throw ContainerError.invalidFormat }

        let b0 = UInt32(data[offset])
        let b1 = UInt32(data[offset + 1]) << 8
        let b2 = UInt32(data[offset + 2]) << 16
        let b3 = UInt32(data[offset + 3]) << 24
        offset += 4

        return b0 | b1 | b2 | b3
    }

    internal mutating func readUInt64LE() throws -> UInt64 {
        guard remainingCount >= 8 else { throw ContainerError.invalidFormat }

        let b0 = UInt64(data[offset])
        let b1 = UInt64(data[offset + 1]) << 8
        let b2 = UInt64(data[offset + 2]) << 16
        let b3 = UInt64(data[offset + 3]) << 24
        let b4 = UInt64(data[offset + 4]) << 32
        let b5 = UInt64(data[offset + 5]) << 40
        let b6 = UInt64(data[offset + 6]) << 48
        let b7 = UInt64(data[offset + 7]) << 56
        offset += 8

        return b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7
    }

    internal mutating func skip(count: Int) throws {
        guard count >= 0 else { throw ContainerError.invalidFormat }
        guard count <= remainingCount else { throw ContainerError.invalidFormat }
        offset += count
    }
}

/// A writer for little-endian binary formats.
internal struct BinaryWriter {
    private(set) var data: Data

    internal init(capacity: Int = 0) {
        if capacity > 0 {
            data = Data(capacity: capacity)
        } else {
            data = Data()
        }
    }

    internal mutating func append(_ bytes: Data) {
        data.append(bytes)
    }

    internal mutating func appendUInt16LE(_ value: UInt16) {
        var val = value.littleEndian
        withUnsafeBytes(of: &val) { buffer in
            data.append(contentsOf: buffer)
        }
    }

    internal mutating func appendUInt32LE(_ value: UInt32) {
        var val = value.littleEndian
        withUnsafeBytes(of: &val) { buffer in
            data.append(contentsOf: buffer)
        }
    }

    internal mutating func appendUInt64LE(_ value: UInt64) {
        var val = value.littleEndian
        withUnsafeBytes(of: &val) { buffer in
            data.append(contentsOf: buffer)
        }
    }
}
