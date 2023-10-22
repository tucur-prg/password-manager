//
//  CredentialProviderViewController.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/19.
//

import AuthenticationServices

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
            
            logCredentialRequest(passkeyRequest)

            let recordIdentifier = passkeyCredentialIdentity.recordIdentifier!

            let rpId = passkeyCredentialIdentity.relyingPartyIdentifier
            let userHandle = passkeyCredentialIdentity.userHandle
            let credentialId = passkeyCredentialIdentity.credentialID

            let assertion = Assertion(rpId: rpId)

            let authenticatorData = assertion.toData()
            var signature: Data?

            var message = Data()
            message.append(authenticatorData)
            message.append(passkeyRequest.clientDataHash)
            
            let ecc = Ecc(alias: recordIdentifier)

            do {
                signature = try ecc.signature(message)
            } catch {
                // extensionContext.cancelRequest を投げる
                NSLog("error")
            }

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
            
            logCredentialRequest(passwordRequest)
            
            let user = passwordCredentialIdentity.user

            // パスワード情報をRecordIdentifierの値を使って引き出す
            let passwordCredential = ASPasswordCredential(user: user, password: "xxxx")
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
        let passkeyRequest = registrationRequest as! ASPasskeyCredentialRequest
        let passkeyCredentialIdentity = passkeyRequest.credentialIdentity as! ASPasskeyCredentialIdentity
        
        logCredentialRequest(passkeyRequest)

        let recordIdentifier = "sample"

        let rpId = passkeyCredentialIdentity.relyingPartyIdentifier
        let userName = passkeyCredentialIdentity.userName
        let userHandle = passkeyCredentialIdentity.userHandle
        var credentialId: Data?

        var attestationObject: Data?

        let ecc = Ecc(alias: recordIdentifier)

        do {
            let key = try ecc.getPublicKey()

            let attestation = Attestation(rpId: rpId)
            try attestation.setECPublicKey(publicKey: key)
            credentialId = attestation.getCredentialId()
            attestationObject = try attestation.toCBOR()
        } catch {
            // extensionContext.cancelRequest を投げる
            NSLog("error")
        }

        NSLog(attestationObject!.hexEncodedString())
        NSLog(attestationObject!.base64EncodedString())

        let passkeyCredential = ASPasskeyRegistrationCredential(
            relyingParty: rpId,
            clientDataHash: passkeyRequest.clientDataHash,
            credentialID: credentialId!,
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
                    credentialID: credentialId!,
                    userHandle: userHandle,
                    recordIdentifier: recordIdentifier
                )

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

    // パスワードリクエストのログ
    private func logCredentialRequest(_ passwordRequest: ASPasswordCredentialRequest) {
        let passwordCredentialIdentity = passwordRequest.credentialIdentity as! ASPasswordCredentialIdentity

        NSLog("User: \(passwordCredentialIdentity.user)")
        NSLog("Rank: \(passwordCredentialIdentity.rank)")
        NSLog("RecordIdentifier: \(passwordCredentialIdentity.recordIdentifier ??  "<nil>")")
    }

    // パスキーリクエストのログ
    private func logCredentialRequest(_ passkeyRequest: ASPasskeyCredentialRequest) {
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
        NSLog("RecordIdentifier: \(passkeyCredentialIdentity.recordIdentifier ??  "<nil>")")
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
                    recordIdentifier: "sample"  // パスワードを引き出すのに使うキーとして使う
                )

                store.saveCredentialIdentities([credential as ASCredentialIdentity]) { bool, error in
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
}
