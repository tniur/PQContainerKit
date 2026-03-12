//
//  ContainerV1InspectTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 12.03.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("Container v1: inspect")
struct ContainerV1InspectTests {
    @Test("inspectContainer returns correct header")
    func inspectContainerReturnsCorrectHeader() throws {
        let owner = try XWing.generateKeyPair()
        let containerID = ContainerID.random()

        let containerData = try ContainerV1.createContainer(
            plaintext: Data("hello".utf8),
            recipients: [],
            owner: owner.publicKey,
            containerID: containerID
        )

        let info = try ContainerV1.inspectContainer(containerData)
        #expect(info.header.algId == .xwingHkdfSha256Aes256Gcm)
        #expect(info.header.containerID == containerID)
        #expect(info.header.recipientsCount == 1)
    }

    @Test("inspectContainer returns all recipient fingerprints")
    func inspectContainerReturnsAllRecipientFingerprints() throws {
        let owner = try XWing.generateKeyPair()
        let alice = try XWing.generateKeyPair()
        let bob = try XWing.generateKeyPair()

        let containerData = try ContainerV1.createContainer(
            plaintext: Data("hello".utf8),
            recipients: [alice.publicKey, bob.publicKey],
            owner: owner.publicKey
        )

        let info = try ContainerV1.inspectContainer(containerData)
        #expect(info.recipientKeyIds.count == 3)
        #expect(info.recipientKeyIds.contains(owner.publicKey.fingerprint))
        #expect(info.recipientKeyIds.contains(alice.publicKey.fingerprint))
        #expect(info.recipientKeyIds.contains(bob.publicKey.fingerprint))
    }

    @Test("containsRecipient(publicKey) returns true for recipient")
    func containsRecipientPublicKeyTrueForRecipient() throws {
        let owner = try XWing.generateKeyPair()
        let alice = try XWing.generateKeyPair()

        let containerData = try ContainerV1.createContainer(
            plaintext: Data("hello".utf8),
            recipients: [alice.publicKey],
            owner: owner.publicKey
        )

        let info = try ContainerV1.inspectContainer(containerData)
        #expect(info.containsRecipient(alice.publicKey))
        #expect(info.containsRecipient(owner.publicKey))
    }

    @Test("containsRecipient(publicKey) returns false for non-recipient")
    func containsRecipientPublicKeyFalseForNonRecipient() throws {
        let owner = try XWing.generateKeyPair()
        let stranger = try XWing.generateKeyPair()

        let containerData = try ContainerV1.createContainer(
            plaintext: Data("hello".utf8),
            recipients: [],
            owner: owner.publicKey
        )

        let info = try ContainerV1.inspectContainer(containerData)
        #expect(!info.containsRecipient(stranger.publicKey))
    }

    @Test("containsRecipient(fingerprint) works correctly")
    func containsRecipientFingerprintWorks() throws {
        let owner = try XWing.generateKeyPair()
        let alice = try XWing.generateKeyPair()
        let stranger = try XWing.generateKeyPair()

        let containerData = try ContainerV1.createContainer(
            plaintext: Data("hello".utf8),
            recipients: [alice.publicKey],
            owner: owner.publicKey
        )

        let info = try ContainerV1.inspectContainer(containerData)
        #expect(info.containsRecipient(alice.publicKey.fingerprint))
        #expect(!info.containsRecipient(stranger.publicKey.fingerprint))
    }

    @Test("inspectContainer throws on invalid data")
    func inspectContainerThrowsOnInvalidData() throws {
        #expect(throws: ContainerError.self) {
            try ContainerV1.inspectContainer(Data())
        }

        #expect(throws: ContainerError.self) {
            try ContainerV1.inspectContainer(Data("not a container".utf8))
        }

        let owner = try XWing.generateKeyPair()
        let containerData = try ContainerV1.createContainer(
            plaintext: Data("hello".utf8),
            recipients: [],
            owner: owner.publicKey
        )

        #expect(throws: ContainerError.self) {
            try ContainerV1.inspectContainer(containerData.prefix(20))
        }
    }
}
