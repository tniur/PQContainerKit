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
    public static func inspectContainer(_ containerData: Data) throws -> ContainerInfo {
        try ContainerV1Validator.inspect(containerData: containerData)
    }

    public static func createContainer(
        plaintext: Data,
        recipients: [XWing.PublicKey],
        owner: XWing.PublicKey,
        containerID: ContainerID = .random()
    ) throws -> Data {
        let uniqueRecipients = makeUniqueRecipients(owner: owner, recipients: recipients)
        guard uniqueRecipients.count <= ContainerV1Constants.maxRecipients else { throw ContainerError.limitsExceeded }

        do {
            return try encryptPayload(plaintext, recipients: uniqueRecipients, containerID: containerID)
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
            return try decryptPayload(from: decoded, myPrivateKey: myPrivateKey, myPublicKey: myPublicKey)
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
            let plaintext = try decryptPayload(from: decoded, myPrivateKey: myPrivateKey, myPublicKey: myPublicKey)

            let uniqueRecipients = makeUniqueRecipients(owner: myPublicKey, recipients: remainingRecipients)
            guard uniqueRecipients.count <= ContainerV1Constants.maxRecipients else {
                throw ContainerError.limitsExceeded
            }

            return try encryptPayload(
                plaintext,
                recipients: uniqueRecipients,
                containerID: decoded.header.containerID,
                algId: decoded.header.algId
            )
        } catch let error as ContainerError {
            throw error
        } catch {
            throw ContainerError.cannotOpen
        }
    }

    private static func decryptPayload(
        from decoded: DecodedContainerV1,
        myPrivateKey: XWing.PrivateKey,
        myPublicKey: XWing.PublicKey
    ) throws -> Data {
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

        let paddedPayload = try ChunkCrypto.decryptPayload(
            chunks: decoded.cipherData.chunks,
            key: dek,
            baseNonce: decoded.cipherData.baseNonce,
            containerID: decoded.header.containerID.rawValue
        )

        return try Padme.unpad(paddedPayload)
    }

    private static func encryptPayload(
        _ plaintext: Data,
        recipients: [XWing.PublicKey],
        containerID: ContainerID,
        algId: AlgId = .xwingHkdfSha256Aes256Gcm
    ) throws -> Data {
        var dekBytes = try randomBytes(count: 32)
        let dek = SymmetricKey(data: dekBytes)
        dekBytes.resetBytes(in: 0 ..< dekBytes.count)

        let entries = try makeRecipientEntries(recipients: recipients, dek: dek, containerID: containerID)

        let paddedPayload = try Padme.pad(plaintext)
        let baseNonce = try randomBytes(count: ChunkCrypto.baseNonceByteCount)
        let chunks = try ChunkCrypto.encryptPayload(
            paddedPayload,
            key: dek,
            baseNonce: baseNonce,
            chunkSize: ContainerV1Constants.defaultChunkSize,
            containerID: containerID.rawValue
        )

        let cipherData = ChunkedCipherData(
            baseNonce: baseNonce,
            chunkSize: UInt32(ContainerV1Constants.defaultChunkSize),
            totalPayloadSize: UInt64(paddedPayload.count),
            chunks: chunks
        )

        let header = try ContainerHeader(
            algId: algId,
            containerID: containerID,
            recipientsCount: UInt16(entries.count)
        )

        return try ContainerV1Encoder.encode(header: header, recipients: entries, cipherData: cipherData)
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
