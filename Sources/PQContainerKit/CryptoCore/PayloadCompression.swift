//
//  PayloadCompression.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 15.03.2026.
//

import Foundation

internal enum PayloadCompression {
    static func compress(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return data }

        do {
            return try (data as NSData).compressed(using: .zlib) as Data
        } catch {
            throw ContainerError.cannotOpen
        }
    }

    static func decompress(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return data }

        do {
            return try (data as NSData).decompressed(using: .zlib) as Data
        } catch {
            throw ContainerError.cannotOpen
        }
    }

    static func tryCompress(_ data: Data) throws -> (data: Data, compressed: Bool) {
        guard !data.isEmpty else { return (data, false) }

        let compressed = try compress(data)

        if compressed.count < data.count {
            return (compressed, true)
        }

        return (data, false)
    }
}
