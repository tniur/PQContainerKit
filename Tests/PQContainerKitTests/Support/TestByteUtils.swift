//
//  TestByteUtils.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 23.02.2026.
//

import CryptoKit
import Foundation

internal enum TestByteUtils {
    static func data(of key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }
}

internal extension FixedWidthInteger {
    var littleEndianBytes: [UInt8] {
        withUnsafeBytes(of: littleEndian) { Array($0) }
    }
}
