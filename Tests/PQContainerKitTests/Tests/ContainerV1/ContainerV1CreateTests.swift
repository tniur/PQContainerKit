//
//  ContainerV1CreateTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 24.02.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("Container v1: create")
struct ContainerV1CreateTests {
    @Test("createContainer produces v1 container that passes structural validation")
    func createContainerProducesValidFormat() throws {
        let owner = try MLKEM768.generateKeyPair()
        let alice = try MLKEM768.generateKeyPair()

        let plaintext = Data("hello".utf8)
        let containerData = try ContainerV1.createContainer(
            plaintext: plaintext,
            recipients: [alice.publicKey],
            owner: owner.publicKey
        )

        let header = try ContainerV1Validator.validate(containerData: containerData)
        #expect(header.algId == .mlkem768HkdfSha256Aes256Gcm)
        #expect(header.recipientsCount == 2)

        let decoded = try ContainerV1Decoder.decode(containerData)
        #expect(decoded.recipients.count == 2)
    }

    @Test("createContainer deduplicates recipients by fingerprint and always includes owner")
    func createContainerDeduplicatesRecipients() throws {
        let owner = try MLKEM768.generateKeyPair()
        let alice = try MLKEM768.generateKeyPair()

        let plaintext = Data("hello".utf8)
        let containerData = try ContainerV1.createContainer(
            plaintext: plaintext,
            recipients: [alice.publicKey, owner.publicKey, alice.publicKey],
            owner: owner.publicKey
        )

        let header = try ContainerV1Validator.validate(containerData: containerData)
        #expect(header.recipientsCount == 2)

        let decoded = try ContainerV1Decoder.decode(containerData)
        #expect(decoded.recipients.count == 2)
    }
}
