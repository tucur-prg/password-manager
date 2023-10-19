//
//  FirstViewController.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/19.
//

import UIKit
import AuthenticationServices

class FirstViewController: ASCredentialProviderViewController {

    static let identifier = "FirstViewController"
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    @IBAction func cancel(_ sender: AnyObject?) {
        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }
}
