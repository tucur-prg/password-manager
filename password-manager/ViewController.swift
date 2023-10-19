//
//  ViewController.swift
//  password-manager
//
//  Created by n-shirasaki on 2023/10/19.
//

import UIKit
import AuthenticationServices

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.

        let store = ASCredentialIdentityStore.shared;
        store.getState {state in
            NSLog("Checked: %@", state)
            if state.isEnabled {
                let credential = ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: "localhost:8000", type: .domain),
                            user: "Username",
                            recordIdentifier: "my_reference_to_the_password_data")

                store.saveCredentialIdentities([credential], completion: { bool, error in
                    if let error = error {
                        NSLog(error.localizedDescription)
                    } else {
                        print("success")
                    }
                })
            }
        }

    }


}

