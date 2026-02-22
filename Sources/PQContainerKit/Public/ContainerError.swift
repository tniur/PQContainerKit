//
//  ContainerError.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

/// Public error type for the container/protocol layer.
///
/// These errors are coarse-grained by design to avoid leaking cryptographic details
/// (e.g. "wrong key" vs "tampered ciphertext").
public enum ContainerError: Error, Equatable, Sendable {
    /// The container version is not supported by this build.
    case unsupportedVersion
    /// The container file is malformed (invalid structure, wrong lengths, unexpected EOF).
    case invalidFormat
    /// Parsed values exceed configured limits (e.g. recipients count, field sizes).
    case limitsExceeded
    /// The current key material has no access to this container (no matching recipient entry).
    case accessDenied
    /// The container cannot be opened (generic failure that must not reveal details).
    case cannotOpen
}
