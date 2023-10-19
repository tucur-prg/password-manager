//
//  CredentialProviderViewController.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/19.
//

import AuthenticationServices

class CredentialProviderViewController: ASCredentialProviderViewController {

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        // AutoFilの鍵マークをクリックした時に実行されるところ
        NSLog("call: prepareCredentialList")
        NSLog("URL: %@", serviceIdentifiers[0].identifier)
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        NSLog("call: provideCredentialWithoutUserInteraction")

        let passwordCredential = ASPasswordCredential(user: "xxxx", password: "xxxx")
        self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
      NSLog("call: prepareInterfaceToProvideCredential")
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        NSLog("call: prepareInterface")
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

    @IBAction func cancel(_ sender: AnyObject?) {
        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }

    @IBAction func passwordSelected(_ sender: AnyObject?) {
        let passwordCredential = ASPasswordCredential(user: "j_appleseed", password: "apple1234")
        self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

}
