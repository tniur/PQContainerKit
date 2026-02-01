//
//  Error.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

public extension PQContainerKit {
    enum Error: Swift.Error, Equatable, Sendable {
        case invalidBase64
        case invalidKeyRepresentation
        case keyGenerationFailed
    }
}
