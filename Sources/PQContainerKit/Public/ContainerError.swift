//
//  ContainerError.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 22.02.2026.
//

import Foundation

public enum ContainerError: Error, Equatable, Sendable {
    case unsupportedVersion
    case invalidFormat
    case limitsExceeded
    case accessDenied
    case cannotOpen
}
