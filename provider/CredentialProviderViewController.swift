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

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        // AutoFilの鍵マークをクリックした時に実行されるところ
        NSLog("call: prepareCredentialList")
        NSLog("Class: %@", serviceIdentifiers[0])
        NSLog("URL: %@", serviceIdentifiers[0].identifier)
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        NSLog("call: provideCredentialWithoutUserInteraction")
        NSLog("Class: %@", credentialIdentity)

        let passwordCredential = ASPasswordCredential(user: "xxxx", password: "xxxx")
        self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        NSLog("call: prepareInterfaceToProvideCredential")
    }

    // Create a passkey? の画面で Continue ボタンを押した時に呼び出される
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        NSLog("call: prepareInterface")
        let encoder = CBOREncoder()
        let passkeyRequest = registrationRequest as! ASPasskeyCredentialRequest
        let passkeyCredentialIdentity = passkeyRequest.credentialIdentity as! ASPasskeyCredentialIdentity

        NSLog("UserName: \(passkeyCredentialIdentity.userName)")
        NSLog("RelyingPartyIdentifier: \(passkeyCredentialIdentity.relyingPartyIdentifier)")
        NSLog("ClientDataHash: \(passkeyRequest.clientDataHash.description)")

        /*
        attestationObject
          .fmt
          .attStmt
            .alg
            .sig Uint8
          .authData Uint8 => | 32 byte rpIdHash | 1 byte flags | 4 byte signCount | 16 byte aaguid | 2 byte credentialIdLength | x byte credentialId | x byte publicKeyCbor |
              publicKeyCbor => { 1: 2, 3: -7, -1: 1, -2: Uint8 , -3: Uint8}
        */

        let rpIdHash = Data(SHA256.hash(data: passkeyCredentialIdentity.relyingPartyIdentifier.data(using: .utf8)!))
        let flags = Data([ UInt8(0x01 | 0x04 | 0x40 | 0x80) ])
        let signCount = Data([0, 0, 0, 0])
        let aaguid = Data([0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7])
        let credentialIdLength = Data([0, 32])
        let credentialId = Data([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        var credentialPublicKey = Data()
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
                    typ: 2,
                    alg: -7,
                    crv: 1,
                    x: k2.subdata(in: 1..<33),
                    y: k2.subdata(in: 33..<65)
                )
            )
            NSLog(credentialPublicKey.hexEncodedString())
        } catch {
            NSLog("error")
        }

        let authData = rpIdHash + flags + signCount + aaguid + credentialIdLength + credentialId + credentialPublicKey

        NSLog(rpIdHash.hexEncodedString())
        NSLog(flags.hexEncodedString())
        NSLog(signCount.hexEncodedString())
        NSLog(aaguid.hexEncodedString())
        NSLog(credentialIdLength.hexEncodedString())
        NSLog(credentialId.hexEncodedString())

        NSLog(authData.hexEncodedString())

        var attestationObject = Data()
        do {
            attestationObject = try encoder.encode(
                AttestationObject(
                    fmt: "packed",
                    attStmt: AttStmt(alg: -7, sig: Data()),
                    authData: authData
                )
            )
        } catch {
            NSLog("error")
        }

        NSLog(attestationObject.hexEncodedString())
        NSLog(attestationObject.base64EncodedString())

        let passkeyCredential = ASPasskeyRegistrationCredential(
            relyingParty: passkeyCredentialIdentity.relyingPartyIdentifier,
            clientDataHash: passkeyRequest.clientDataHash,
            credentialID: credentialId,
            attestationObject: attestationObject
        )

        self.extensionContext.completeRegistrationRequest(using: passkeyCredential, completionHandler: nil)
    }

    override func prepareInterfaceForExtensionConfiguration() {
        NSLog("call: prepareInterfaceForExtensionConfiguration")

        // パスワードオプションのところで呼び出されるカスタムUI
        let sb = UIStoryboard(name: "FirstView", bundle: nil)

        let vc = sb.instantiateInitialViewController() as! FirstViewController

        vc.modalPresentationStyle = .fullScreen

        present(vc, animated: true)
    }

    override func viewDidLoad() {
        NSLog("call: viewDidLoad")
        super.viewDidLoad()
    }

    override func viewDidAppear(_ animated: Bool) {
        NSLog("call: viewDidAppear")
        super.viewDidAppear(animated)
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
                        NSLog("save success")
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
    var attStmt: AttStmt
    var authData: Data
}

struct AttStmt: Codable {
    var alg: Int
    var sig: Data
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
