//
//  Extensions.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/22.
//

import Foundation

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
