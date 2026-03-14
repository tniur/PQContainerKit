//
//  Padme.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 14.03.2026.
//

import Foundation
import Security

internal enum Padme {
    private static let lengthPrefixSize = 8

    static func paddedLength(_ length: Int) -> Int {
        guard length > 2 else { return length }

        let exponent = Int.bitWidth - 1 - length.leadingZeroBitCount
        let significantBits = Int.bitWidth - 1 - exponent.leadingZeroBitCount + 1
        let zeroBits = exponent - significantBits

        guard zeroBits > 0 else {
            return length
        }

        let mask = (1 << zeroBits) - 1

        return (length + mask) & ~mask
    }

    static func pad(_ plaintext: Data) throws -> Data {
        let payloadLength = lengthPrefixSize + plaintext.count
        let targetLength = paddedLength(payloadLength)
        let paddingCount = targetLength - payloadLength

        var result = Data(capacity: targetLength)

        var lengthLE = UInt64(plaintext.count).littleEndian
        result.append(Data(bytes: &lengthLE, count: lengthPrefixSize))
        result.append(plaintext)

        if paddingCount > 0 {
            var padding = Data(count: paddingCount)
            let status: OSStatus = padding.withUnsafeMutableBytes { raw in
                guard let base = raw.baseAddress else { return errSecParam }
                return SecRandomCopyBytes(kSecRandomDefault, paddingCount, base)
            }

            guard status == errSecSuccess else {
                throw ContainerError.cannotOpen
            }

            result.append(padding)
        }

        return result
    }

    static func unpad(_ payload: Data) throws -> Data {
        guard payload.count >= lengthPrefixSize else {
            throw ContainerError.invalidFormat
        }

        let lengthBytes = payload.prefix(lengthPrefixSize)
        let originalLength = lengthBytes.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
        let length = Int(UInt64(littleEndian: originalLength))

        guard length >= 0, lengthPrefixSize + length <= payload.count else {
            throw ContainerError.invalidFormat
        }

        return payload[lengthPrefixSize ..< lengthPrefixSize + length]
    }
}
