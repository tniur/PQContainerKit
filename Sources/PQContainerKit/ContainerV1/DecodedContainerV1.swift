//
//  DecodedContainerV1.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

internal struct DecodedContainerV1: Sendable {
    internal let header: ContainerHeader
    internal let recipients: [RecipientEntry]
    internal let cipherParts: CipherParts
}
