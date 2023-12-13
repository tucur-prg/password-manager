//
//  Attestation.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/22.
//

import Foundation
import CryptoKit
import CBORCoding

class Attestation : NSObject {
    var encoder = CBOREncoder()

    var rpIdHash: Data
    var flags: Data
    var signCount: Data = Data([0, 0, 0, 0])
    var aaguid: Data = Data([0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7])
    var credentialId: Data
    var credentialIdLength: Data
    var credentialPublicKey: Data?
    
    init(rpId: String) {
        self.rpIdHash = Data(SHA256.hash(data: rpId.data(using: .utf8)!))
        self.flags = Data([ UInt8(UP | UV | BE | BS | AT) ])
        self.credentialId = Data([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        self.credentialIdLength = Data([0, UInt8(self.credentialId.count)])
    }
    
    func setECPublicKey(publicKey: Data) throws -> Void {
        credentialPublicKey = try encoder.encode(
            CredentialPublicKeyEc(
                typ: EC2,
                alg: ES256,
                crv: P256,
                x: publicKey.subdata(in: 1..<33),
                y: publicKey.subdata(in: 33..<65)
            )
        )
    }
    
    func generateAuthData() throws -> Data {
        var authData: Data = Data()
        
        if credentialPublicKey == nil {
            throw NSError(domain: "credentialPublicKey is empty", code: 0, userInfo: nil)
        }

        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(signCount)
        authData.append(aaguid)
        authData.append(credentialIdLength)
        authData.append(credentialId)
        authData.append(credentialPublicKey!)
        
        return authData
    }
    
    func getCredentialId() -> Data {
        return credentialId
    }
    
    func toCBOR() throws -> Data {
        return try encoder.encode(
            AttestationObject(
                fmt: "none", // "packed"は未対応だった
                attStmt: [String:String](),
                authData: try generateAuthData()
            )
        )
    }
}

struct AttestationObject: Codable {
    var fmt: String
    var attStmt: [String: String]
    var authData: Data
}

struct CredentialPublicKeyEc: Codable {
    var typ: Int
    var alg: Int
    var crv: Int
    var x: Data
    var y: Data

    private enum CodingKeys: Int, CodingKey {
        case typ = 1
        case alg = 3
        case crv = -1
        case x = -2
        case y = -3
    }
}
