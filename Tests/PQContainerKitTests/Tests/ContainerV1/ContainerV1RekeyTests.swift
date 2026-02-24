//
//  ContainerV1RekeyTests.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 24.02.2026.
//

import Foundation
@testable import PQContainerKit
import Testing

@Suite("Container v1: rekey")
struct ContainerV1RekeyTests {
    @Test("rekeyContainer revokes removed recipient")
    func rekeyRevokesRecipient() throws {
        let owner = try MLKEM768.generateKeyPair()
        let alice = try MLKEM768.generateKeyPair()
        let bob = try MLKEM768.generateKeyPair()

        let plaintext = Data("top-secret".utf8)
        let containerData = try ContainerV1.createContainer(
            plaintext: plaintext,
            recipients: [alice.publicKey, bob.publicKey],
            owner: owner.publicKey
        )

        let decodedOld = try ContainerV1Decoder.decode(containerData)

        let newData = try ContainerV1.rekeyContainer(
            containerData: containerData,
            remainingRecipients: [alice.publicKey],
            myPrivateKey: owner.privateKey,
            myPublicKey: owner.publicKey
        )

        let decodedNew = try ContainerV1Decoder.decode(newData)
        #expect(decodedNew.header.containerID == decodedOld.header.containerID)
        #expect(decodedNew.recipients.count == 2)

        let openedOwner = try ContainerV1.openContainer(
            containerData: newData,
            myPrivateKey: owner.privateKey,
            myPublicKey: owner.publicKey
        )
        #expect(openedOwner == plaintext)

        let openedAlice = try ContainerV1.openContainer(
            containerData: newData,
            myPrivateKey: alice.privateKey,
            myPublicKey: alice.publicKey
        )
        #expect(openedAlice == plaintext)

        #expect(throws: ContainerError.accessDenied) {
            _ = try ContainerV1.openContainer(
                containerData: newData,
                myPrivateKey: bob.privateKey,
                myPublicKey: bob.publicKey
            )
        }
    }
}
