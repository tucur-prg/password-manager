//
//  CredentialProviderViewController.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/19.
//

import CryptoKit
import AuthenticationServices
import Security
import CBORCoding

class CredentialProviderViewController: ASCredentialProviderViewController {

    // AutoFilの鍵マークをクリックした時に実行されるところ
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        NSLog("call: prepareCredentialList deprecated")
        NSLog("Class: %@", serviceIdentifiers[0])
        NSLog("URL: %@", serviceIdentifiers[0].identifier)
    }

    // 
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {

        NSLog("call: prepareCredentialList")
        NSLog("Class: %@", serviceIdentifiers[0])
        NSLog("URL: %@", serviceIdentifiers[0].identifier)
    }

    // AutoFilで ASCredentialIdentityStore に保存したユーザー名をクリックした時によばれる
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        NSLog("call: provideCredentialWithoutUserInteraction deprecated")
        NSLog("Class: %@", credentialIdentity)

        let passwordCredential = ASPasswordCredential(user: "xxxx", password: "xxxx")
        self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

    // info.plist の ProvidesPasskeys = true
    // AutoFilで ASCredentialIdentityStore に保存したユーザー名をクリックした時によばれる
    // Sign in with your passkey? の画面で Continue ボタンを押した時に呼び出される
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        NSLog("call: provideCredentialWithoutUserInteraction")
        // ASCredentialRequest.type をみてハンドリング
        if credentialRequest.type == .passkeyAssertion {
            let passkeyRequest = credentialRequest as! ASPasskeyCredentialRequest
            let passkeyCredentialIdentity = passkeyRequest.credentialIdentity as! ASPasskeyCredentialIdentity
            
            NSLog("ClientDataHash: \(passkeyRequest.clientDataHash.hexEncodedString())")
            NSLog("UserVerification: \(passkeyRequest.userVerificationPreference.rawValue)")
            for alg in passkeyRequest.supportedAlgorithms {
                NSLog("Alg: \(alg.rawValue)")
            }
            
            NSLog("User: \(passkeyCredentialIdentity.user)")
            NSLog("UserName: \(passkeyCredentialIdentity.userName)")
            NSLog("RelyingPartyIdentifier: \(passkeyCredentialIdentity.relyingPartyIdentifier)")
            NSLog("Rank: \(passkeyCredentialIdentity.rank)")
            NSLog("UserHandle: \(passkeyCredentialIdentity.userHandle.hexEncodedString())")
            NSLog("CredentialID: \(passkeyCredentialIdentity.credentialID.hexEncodedString())")
            
            NSLog(passkeyCredentialIdentity.recordIdentifier ??  "<nil>")
            
            var authenticatorData = Data()
            
            let rpId = passkeyCredentialIdentity.relyingPartyIdentifier
            let userHandle = passkeyCredentialIdentity.userHandle
            
            let rpIdHash = Data(SHA256.hash(data: rpId.data(using: .utf8)!))
            let flags = Data([ UInt8(0x01 | 0x04 | 0x08 | 0x10) ])
            let signCount = Data([0, 0, 0, 0])
            let credentialId = passkeyCredentialIdentity.credentialID
            
            authenticatorData.append(rpIdHash)
            authenticatorData.append(flags)
            authenticatorData.append(signCount)
            
            var signature: Data?
            do {
                var error: Unmanaged<CFError>?
                
                guard let privateKey = load("sample") else {
                    throw NSError(domain: "privateKey", code: -1, userInfo: nil)
                }
                
                let message = authenticatorData + passkeyRequest.clientDataHash
                guard let res = SecKeyCreateSignature(
                    privateKey,
                    .ecdsaSignatureMessageX962SHA256,
                    message as CFData,
                    &error) as Data?
                else {
                    throw NSError(domain: "sign error", code: -1, userInfo: nil)
                }
                
                signature = res
            } catch {
                NSLog("error")
            }
            
            NSLog(rpIdHash.hexEncodedString())
            NSLog(flags.hexEncodedString())
            NSLog(signCount.hexEncodedString())
            NSLog(credentialId.hexEncodedString())
            
            NSLog(authenticatorData.hexEncodedString())
            NSLog(authenticatorData.base64EncodedString())
            
            let passkeyCredential = ASPasskeyAssertionCredential(
                userHandle: userHandle,
                relyingParty: rpId,
                signature: signature!,
                clientDataHash: passkeyRequest.clientDataHash,
                authenticatorData: authenticatorData,
                credentialID: credentialId
            )
            
            self.extensionContext.completeAssertionRequest(using: passkeyCredential) { success in
                if success {
                    NSLog("completeAssertionRequest success")
                } else {
                    NSLog("completeAssertionRequest failer")
                }
            }
        } else {
            let passwordRequest = credentialRequest as! ASPasswordCredentialRequest
            let passwordCredentialIdentity = passwordRequest.credentialIdentity as! ASPasswordCredentialIdentity

            NSLog("User: \(passwordCredentialIdentity.user)")
            NSLog("Rank: \(passwordCredentialIdentity.rank)")
            
            NSLog(passwordCredentialIdentity.recordIdentifier ??  "<nil>")

            let passwordCredential = ASPasswordCredential(user: "xxxx", password: "xxxx")
            self.extensionContext.completeRequest(withSelectedCredential: passwordCredential) { success in
                if success {
                    NSLog("completeRequest success")
                } else {
                    NSLog("completeRequest failer")
                }
            }
        }
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASPasswordCredentialIdentity) {
        NSLog("call: prepareInterfaceToProvideCredential deprecated")
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        NSLog("call: prepareInterfaceToProvideCredential")
    }

    // info.plist の ProvidesPasskeys = true
    // Create a passkey? の画面で Continue ボタンを押した時に呼び出される
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        NSLog("call: prepareInterface")
        let encoder = CBOREncoder()
        let passkeyRequest = registrationRequest as! ASPasskeyCredentialRequest
        let passkeyCredentialIdentity = passkeyRequest.credentialIdentity as! ASPasskeyCredentialIdentity

        NSLog("ClientDataHash: \(passkeyRequest.clientDataHash.hexEncodedString())")
        NSLog("UserVerification: \(passkeyRequest.userVerificationPreference.rawValue)")
        for alg in passkeyRequest.supportedAlgorithms {
            NSLog("Alg: \(alg.rawValue)")
        }

        NSLog("User: \(passkeyCredentialIdentity.user)")
        NSLog("UserName: \(passkeyCredentialIdentity.userName)")
        NSLog("RelyingPartyIdentifier: \(passkeyCredentialIdentity.relyingPartyIdentifier)")
        NSLog("Rank: \(passkeyCredentialIdentity.rank)")
        NSLog("UserHandle: \(passkeyCredentialIdentity.userHandle.hexEncodedString())")
        NSLog("CredentialID: \(passkeyCredentialIdentity.credentialID.hexEncodedString())")

        NSLog(passkeyCredentialIdentity.recordIdentifier ??  "<nil>")

        var authData = Data()
        var attestationObject: Data?
        
        let rpId = passkeyCredentialIdentity.relyingPartyIdentifier
        let userName = passkeyCredentialIdentity.userName
        let userHandle = passkeyCredentialIdentity.userHandle
        
        let rpIdHash = Data(SHA256.hash(data: rpId.data(using: .utf8)!))
        let flags = Data([ UInt8(0x01 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80) ])
        let signCount = Data([0, 0, 0, 0])
        let aaguid = Data([0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7])
        let credentialIdLength = Data([0, 32])
        let credentialId = Data([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        var credentialPublicKey: Data?

        do {
            var error: Unmanaged<CFError>?

            guard let privateKey = load("sample") else {
                throw NSError(domain: "privateKey", code: -1, userInfo: nil)
            }

            let publicKey = SecKeyCopyPublicKey(privateKey)

            guard let k1 = SecKeyCopyExternalRepresentation(publicKey!, &error) else {
                throw NSError(domain: "publicKey", code: -1, userInfo: nil)
            }

            let k2: Data = k1 as Data

            credentialPublicKey = try encoder.encode(
                CredentialPublicKeyEc(
                    typ: 2, // EC2
                    alg: -7, // ES256
                    crv: 1, // P-256
                    x: k2.subdata(in: 1..<33),
                    y: k2.subdata(in: 33..<65)
                )
            )
            
            authData.append(rpIdHash)
            authData.append(flags)
            authData.append(signCount)
            authData.append(aaguid)
            authData.append(credentialIdLength)
            authData.append(credentialId)
            authData.append(credentialPublicKey!)

            attestationObject = try encoder.encode(
                AttestationObject(
                    fmt: "none", // "packed"は未対応だった
                    attStmt: [String:String](),
                    authData: authData
                )
            )
        } catch {
            NSLog("error")
        }

        NSLog(rpIdHash.hexEncodedString())
        NSLog(flags.hexEncodedString())
        NSLog(signCount.hexEncodedString())
        NSLog(aaguid.hexEncodedString())
        NSLog(credentialIdLength.hexEncodedString())
        NSLog(credentialId.hexEncodedString())
        NSLog(credentialPublicKey!.hexEncodedString())

        NSLog(authData.hexEncodedString())

        NSLog(attestationObject!.hexEncodedString())
        NSLog(attestationObject!.base64EncodedString())

        let passkeyCredential = ASPasskeyRegistrationCredential(
            relyingParty: rpId,
            clientDataHash: passkeyRequest.clientDataHash,
            credentialID: credentialId,
            attestationObject: attestationObject!
        )

        self.extensionContext.completeRegistrationRequest(using: passkeyCredential) { success in
            if success {
                NSLog("completeRegistrationRequest success")
            } else {
                NSLog("completeRegistrationRequest failer")
            }
        }

        // completeRegistrationRequest が failer のほうにいくので一旦ここに
        let store = ASCredentialIdentityStore.shared;
        store.getState {state in
            if state.isEnabled {
                // navigator.credentials.get の項目に表示されるようにする
                let credential = ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: rpId,
                    userName: userName,
                    credentialID: credentialId,
                    userHandle: userHandle,
                    recordIdentifier: nil)
                    
                store.saveCredentialIdentities([credential]) { bool, error in
                    if let error = error {
                        NSLog(error.localizedDescription)
                    } else {
                        NSLog("passkey save success")
                    }
                }
            }
        }
    }

    // info.plist の ASCredentialProviderExtensionShowsConfigurationUI = true
    // パスワードオプションのところで呼び出されるカスタムUI
    override func prepareInterfaceForExtensionConfiguration() {
        NSLog("call: prepareInterfaceForExtensionConfiguration")

        let sb = UIStoryboard(name: "FirstView", bundle: nil)

        let vc = sb.instantiateInitialViewController() as! FirstViewController

        vc.modalPresentationStyle = .fullScreen

        present(vc, animated: true)
    }

    override func viewDidLoad() {
        NSLog("call: viewDidLoad")
        super.viewDidLoad()
    }

    @IBAction func cancel(_ sender: AnyObject?) {
        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }

    @IBAction func passwordSelected(_ sender: AnyObject?) {
        let passwordCredential = ASPasswordCredential(user: "j_appleseed", password: "apple1234")
        self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

    @IBAction func save(_ sender: AnyObject?) {
        let store = ASCredentialIdentityStore.shared;
        store.getState {state in
            if state.isEnabled {
                // http://localhost:8000/ で検証　identifier にポートは含めない
                let credential = ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(
                        identifier: "localhost",
                        type: .domain),
                    user: "hogefuga",
                  recordIdentifier: nil)

                store.saveCredentialIdentities([credential]) { bool, error in
                    if let error = error {
                        NSLog(error.localizedDescription)
                    } else {
                        NSLog("password save success")
                    }
                }
            }
        }
    }

    @IBAction func remove(_ sender: AnyObject?) {
        let store = ASCredentialIdentityStore.shared;
        store.getState {state in
            if state.isEnabled {
                store.removeAllCredentialIdentities { bool, error in
                    if let error = error {
                        NSLog(error.localizedDescription)
                    } else {
                        NSLog("removeAll success")
                    }
                }
            }
        }
    }


    func load(_ alias: String) -> SecKey? {
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

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

struct AttestationObject: Codable {
    var fmt: String
    var attStmt: [String: String]
    var authData: Data
}

struct AssrtsionObject: Codable {
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

    private enum CodingKeys: String, CodingKey {
        case typ = "1"
        case alg = "3"
        case crv = "-1"
        case x = "-2"
        case y = "-3"
    }
}
