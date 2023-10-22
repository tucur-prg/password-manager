//
//  Assartion.swift
//  provider
//
//  Created by n-shirasaki on 2023/10/22.
//

import Foundation
import CryptoKit

class Assertion : NSObject {
    var rpIdHash: Data
    var flags: Data
    var signCount: Data = Data([0, 0, 0, 0])
    
    init(rpId: String) {
        self.rpIdHash = Data(SHA256.hash(data: rpId.data(using: .utf8)!))
        self.flags = Data([ UInt8(UP | UV | BE | BS) ])
    }
    
    func toData() -> Data {
        var authenticatorData: Data = Data()
        
        authenticatorData.append(rpIdHash)
        authenticatorData.append(flags)
        authenticatorData.append(signCount)

        return authenticatorData
    }
}
