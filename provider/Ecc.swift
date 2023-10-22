//
//  Ecc.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/22.
//

import Foundation
import Security

class Ecc : NSObject {
    var alias: String

    init(alias: String) {
        self.alias = alias
    }
    
    func getPublicKey() throws -> Data {
        var error: Unmanaged<CFError>?

        guard let privateKey = load(alias) else {
            throw NSError(domain: "privateKey", code: -1, userInfo: nil)
        }

        let publicKey = SecKeyCopyPublicKey(privateKey)
        guard let key = SecKeyCopyExternalRepresentation(publicKey!, &error) else {
            throw NSError(domain: "publicKey", code: -1, userInfo: nil)
        }
        
        return key as Data
    }
    
    func signature(_ message: Data) throws -> Data {
        var error: Unmanaged<CFError>?

        guard let privateKey = load(alias) else {
            throw NSError(domain: "privateKey", code: -1, userInfo: nil)
        }

        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error) as Data?
        else {
            throw NSError(domain: "signature", code: -1, userInfo: nil)
        }

        return signature
    }
    
    private func load(_ alias: String) -> SecKey? {
      var error: Unmanaged<CFError>?

      let query: NSDictionary = [
        kSecClass: kSecClassKey,
        kSecAttrApplicationTag: alias.data(using: .utf8)!,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef: true
      ]

      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      guard status == errSecSuccess else {
        guard let accessControl = SecAccessControlCreateWithFlags(
          kCFAllocatorDefault,
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
          SecAccessControlCreateFlags.privateKeyUsage,
          &error
        ) else {
          return nil
        }

        let attributes: NSDictionary = [
          kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
          kSecAttrKeySizeInBits: 256,
          kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
          kSecPrivateKeyAttrs: [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: alias.data(using: .utf8)!,
            kSecAttrAccessControl: accessControl
          ]
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
          return nil
        }

        return privateKey
      }

      let privateKey = item as! SecKey

      return privateKey
    }
}

