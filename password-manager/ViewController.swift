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
                NSLog("isEnabled")
            }
        }

    }


}
