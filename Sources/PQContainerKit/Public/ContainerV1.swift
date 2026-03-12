//
//  ContainerV1.swift
//  PQContainerKit
//
//  Created by Pavel Bobkov on 24.02.2026.
//

import CryptoKit
import Foundation
import Security

public enum ContainerV1 {
    public static func createContainer(
        plaintext: Data,
        recipients: [XWing.PublicKey],
        owner: XWing.PublicKey,
        containerID: ContainerID = .random()
    ) throws -> Data {
        guard UInt64(plaintext.count) <= ContainerV1Constants.maxCiphertextSize else {
            throw ContainerError.limitsExceeded
        }

        let uniqueRecipients = makeUniqueRecipients(owner: owner, recipients: recipients)
        guard uniqueRecipients.count <= ContainerV1Constants.maxRecipients else { throw ContainerError.limitsExceeded }

        do {
            var dekBytes = try randomBytes(count: 32)
            let dek = SymmetricKey(data: dekBytes)
            dekBytes.resetBytes(in: 0 ..< dekBytes.count)

            let iv = try randomBytes(count: CipherParts.ivByteCount)
            let entries = try makeRecipientEntries(recipients: uniqueRecipients, dek: dek, containerID: containerID)

            let (ciphertext, tag) = try AESGCM.seal(plaintext, key: dek, nonce: iv)
            let cipherParts = try CipherParts(iv: iv, ciphertext: ciphertext, authTag: tag)

            let header = try ContainerHeader(
                algId: .xwingHkdfSha256Aes256Gcm,
                containerID: containerID,
                recipientsCount: UInt16(entries.count)
            )

            return try ContainerV1Encoder.encode(header: header, recipients: entries, cipherParts: cipherParts)
        } catch let error as ContainerError {
            throw error
        } catch {
            throw ContainerError.cannotOpen
        }
    }

    public static func openContainer(
        containerData: Data,
        myPrivateKey: XWing.PrivateKey,
        myPublicKey: XWing.PublicKey
    ) throws -> Data {
        do {
            let decoded = try ContainerV1Decoder.decode(containerData)
            let myKeyId = myPublicKey.fingerprint

            guard let entry = decoded.recipients.first(where: { $0.recipientKeyId == myKeyId }) else {
                throw ContainerError.accessDenied
            }

            let ct = try XWing.Ciphertext(rawRepresentation: entry.kemCiphertext)
            let ss = try XWing.decapsulate(privateKey: myPrivateKey, ciphertext: ct)

            let dek = try DEKWrap.unwrapDEK(
                wrappedDEK: entry.wrappedDEK,
                containerID: decoded.header.containerID.rawValue,
                recipientKeyId: myKeyId.rawValue,
                sharedSecret: ss
            )

            return try AESGCM.open(
                ciphertext: decoded.cipherParts.ciphertext,
                tag: decoded.cipherParts.authTag,
                key: dek,
                nonce: decoded.cipherParts.iv
            )
        } catch let error as ContainerError {
            throw error
        } catch {
            throw ContainerError.cannotOpen
        }
    }

    private static func makeUniqueRecipients(
        owner: XWing.PublicKey,
        recipients: [XWing.PublicKey]
    ) -> [XWing.PublicKey] {
        var seen = Set<Fingerprint>()
        var unique: [XWing.PublicKey] = []

        if seen.insert(owner.fingerprint).inserted {
            unique.append(owner)
        }

        for pk in recipients where seen.insert(pk.fingerprint).inserted {
            unique.append(pk)
        }

        return unique
    }

    public static func rekeyContainer(
        containerData: Data,
        remainingRecipients: [XWing.PublicKey],
        myPrivateKey: XWing.PrivateKey,
        myPublicKey: XWing.PublicKey
    ) throws -> Data {
        do {
            let decoded = try ContainerV1Decoder.decode(containerData)
            let myKeyId = myPublicKey.fingerprint

            guard let entry = decoded.recipients.first(where: { $0.recipientKeyId == myKeyId }) else {
                throw ContainerError.accessDenied
            }

            let ct = try XWing.Ciphertext(rawRepresentation: entry.kemCiphertext)
            let ss = try XWing.decapsulate(privateKey: myPrivateKey, ciphertext: ct)

            let oldDEK = try DEKWrap.unwrapDEK(
                wrappedDEK: entry.wrappedDEK,
                containerID: decoded.header.containerID.rawValue,
                recipientKeyId: myKeyId.rawValue,
                sharedSecret: ss
            )

            let plaintext = try AESGCM.open(
                ciphertext: decoded.cipherParts.ciphertext,
                tag: decoded.cipherParts.authTag,
                key: oldDEK,
                nonce: decoded.cipherParts.iv
            )

            guard UInt64(plaintext.count) <= ContainerV1Constants.maxCiphertextSize else {
                throw ContainerError.limitsExceeded
            }

            let uniqueRecipients = makeUniqueRecipients(owner: myPublicKey, recipients: remainingRecipients)
            guard uniqueRecipients.count <= ContainerV1Constants.maxRecipients else {
                throw ContainerError.limitsExceeded
            }

            var dekBytes = try randomBytes(count: 32)
            let dek = SymmetricKey(data: dekBytes)
            dekBytes.resetBytes(in: 0 ..< dekBytes.count)

            let iv = try randomBytes(count: CipherParts.ivByteCount)
            let entries = try makeRecipientEntries(
                recipients: uniqueRecipients,
                dek: dek, containerID: decoded.header.containerID
            )

            let (ciphertext, tag) = try AESGCM.seal(plaintext, key: dek, nonce: iv)
            let cipherParts = try CipherParts(iv: iv, ciphertext: ciphertext, authTag: tag)

            let header = try ContainerHeader(
                algId: decoded.header.algId,
                containerID: decoded.header.containerID,
                recipientsCount: UInt16(entries.count)
            )

            return try ContainerV1Encoder.encode(header: header, recipients: entries, cipherParts: cipherParts)
        } catch let error as ContainerError {
            throw error
        } catch {
            throw ContainerError.cannotOpen
        }
    }

    private static func makeRecipientEntries(
        recipients: [XWing.PublicKey],
        dek: SymmetricKey,
        containerID: ContainerID
    ) throws -> [RecipientEntry] {
        var entries: [RecipientEntry] = []
        entries.reserveCapacity(recipients.count)

        for pk in recipients {
            let recipientKeyId = pk.fingerprint
            let kem = try XWing.encapsulate(to: pk)
            let wrappedDEK = try DEKWrap.wrapDEK(
                dek: dek,
                containerID: containerID.rawValue,
                recipientKeyId: recipientKeyId.rawValue,
                sharedSecret: kem.sharedSecret
            )

            entries.append(
                RecipientEntry(
                    recipientKeyId: recipientKeyId,
                    kemCiphertext: kem.ciphertext.rawRepresentation,
                    wrappedDEK: wrappedDEK
                )
            )
        }

        return entries
    }

    private static func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)

        let status: OSStatus = data.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else {
                return errSecParam
            }

            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }

        guard status == errSecSuccess else {
            throw ContainerError.cannotOpen
        }

        return data
    }
}
