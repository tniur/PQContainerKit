//
//  ContainerKitError.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 01.02.2026.
//

public enum ContainerKitError: Error, Equatable, Sendable {
    // MARK: - Key

    case invalidBase64

    case invalidKeyRepresentation

    case keyGenerationFailed

    // MARK: - ML-KEM

    case kemEncapsulationFailed

    case kemDecapsulationFailed

    case invalidCiphertextRepresentation

    // MARK: - KDF / AEAD

    case invalidKDFOutputLength

    case invalidNonceLength

    case invalidTagLength

    case aeadFailed

    case invalidWrappedDEKRepresentation
}
