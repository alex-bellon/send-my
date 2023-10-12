//
//  OpenHaystack – Tracking personal Bluetooth devices via Apple's Find My network
//
//  Copyright © 2021 Secure Mobile Networking Lab (SEEMOO)
//  Copyright © 2021 The Open Wireless Link Project
//
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Combine
import Foundation
import SwiftUI
import CryptoKit


func byteArray<T>(from value: T) -> [UInt8] where T: FixedWidthInteger {
    withUnsafeBytes(of: value.bigEndian, Array.init)
}

extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }
    
    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}


class FindMyController: ObservableObject {
    static let shared = FindMyController()
    
    @Published var error: Error?
    @Published var devices = [ModemDevice]()
    @Published var messages = [UInt32: Message]()
    @Published var reps = [FindMyReport]()
    @Published var keys = [String: [UInt8]]()
    @Published var keyHashes = [Data]()
    @Published var findMyKeys = [FindMyKey]()
    @Published var decryptedReports = [FindMyLocationReport]()

    
    func pad(string: String, toSize: Int) -> String {
        var padded = string
        for _ in 0..<(toSize - string.count) {
            padded = "0" + padded
        }
        return padded
    }
    
    func hexString(key: [UInt8]) -> String {
        var hex = String(format:"%02X", key[0])
        for i in 1..<key.count{
            hex += " " + String(format:"%02X", key[i])
        }
        return hex
    }
    
    func hexString(key: Data) -> String {
        var hex = ""
        for i in key {
            hex += String(format:"%02X", i)
        }
        return hex
    }
    
    func generatePublicKeys() {
        var result = ""
        for _ in 0..<2500 {
            var privateKey: Data?
            var publicKey: Data?
            var publicHex = ""
            while publicHex.count != 56 {
                privateKey = BoringSSL.generateNewPrivateKey()
                publicKey = BoringSSL.derivePublicKey(fromPrivateKey: privateKey!)
                publicKey = publicKey!.dropFirst()
                publicHex = hexString(key: privateKey!)
            }
            let line = hexString(key: privateKey!) + "," + hexString(key: publicKey!)
            result.append(line + "\n")
        }
        let outputFile = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("keypairs.txt")
        try? (result.dropLast(1)).write(to: outputFile, atomically: false, encoding: String.Encoding.utf8)
    }
    
    func retreiveForPredeterminedKeys(with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {
        if var dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            
            let homeDirURL = FileManager.default.homeDirectoryForCurrentUser
            let pubURL = homeDirURL.appendingPathComponent("git/LoRa-analysis/experiments/firmware/ble_keys/pubs.txt")
            let privURL = homeDirURL.appendingPathComponent("git/LoRa-analysis/experiments/firmware/ble_keys/privs.txt")
            
            var hashedKeys = [Data]()
            do {
                let pubs_ = try String(contentsOf: pubURL, encoding: .utf8)
                var pubs = pubs_.components(separatedBy: .newlines)
                let privs_ = try String(contentsOf: privURL, encoding: .utf8)
                var privs = privs_.components(separatedBy: .newlines)
                for i in 0..<2500 {
                    var pub = pubs[i]
                    var priv = privs[i]
                    
                    var strPub = pub.split(separator: " ")
                    let intPub = strPub.map{ UInt8($0, radix: 16)! }
                    
                    var strPriv = priv.split(separator: " ")
                    let intPriv = strPriv.map{ UInt8($0, radix: 16)! }
                    
                    var hexPub = String(format:"%02X", intPub[0])
                    for i in 1..<intPub.count{
                        hexPub += " " + String(format:"%02X", intPub[i])
                    }
                    print("Pub key: \(hexPub)")
                    
                    var hexPriv = String(format:"%02X", intPriv[0])
                    for i in 1..<intPriv.count{
                        hexPriv += " " + String(format:"%02X", intPriv[i])
                    }
                    print("Priv key: \(hexPriv)")
                    
                    let keyHash = SHA256.hash(data: intPub).data
                    let b64 = keyHash.base64EncodedString()
                    self.keys[b64] = intPub
                    
                    hashedKeys.append(keyHash)
                    
                    self.findMyKeys.append(
                        FindMyKey(
                            advertisedKey: Data(intPub),
                            hashedKey: keyHash,
                            privateKey: Data(intPriv),
                            startTime: nil,
                            duration: nil,
                            pu: nil,
                            yCoordinate: nil,
                            fullKey: nil)
                    )
                }
                self.keyHashes = hashedKeys
                self.fetchReports(with: searchPartyToken, completion: completion)
            }
            catch {print("Error: could not read file")}
        }
        return
    }
    
    func fetchReports(with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {
        
        DispatchQueue.global(qos: .background).async {
            let fetchReportGroup = DispatchGroup()
            let fetcher = ReportsFetcher()
            
            fetchReportGroup.enter()
            
            var keyEncoded = self.keyHashes.map({ $0.base64EncodedString() })
            
            // 21 days reduced to 1 day
            let duration: Double = (24 * 60 * 60) * 21
            let startDate = Date() - duration
            
            fetcher.query(
                forHashes: keyEncoded,
                start: startDate,
                duration: duration,
                searchPartyToken: searchPartyToken
            ) { jd in
                guard let jsonData = jd else {
                    fetchReportGroup.leave()
                    return
                }
                
                do {
                    let report = try JSONDecoder().decode(FindMyReportResults.self, from: jsonData)
                    self.reps += report.results
                } catch {
                    print("Failed with error \(error)")
                }
                fetchReportGroup.leave()
            }
            
            
            fetchReportGroup.notify(queue: .main) {
                print("Finished loading the reports. Now decrypt them")
                
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else {
                        completion(FindMyErrors.objectReleased)
                        return
                    }
                    
                    self.decryptReports {
                        completion(nil)
                    }
                }
            }
            
            fetchReportGroup.notify(queue: .main) {
                DispatchQueue.main.async {
                    self.decodeReports(with: searchPartyToken) { _ in completion(nil) }
                }
                
            }
        }
    }
    
    func decryptReports(completion: () -> Void) {
        print("Decrypting reports")
        
        let keyMap = self.findMyKeys.reduce(into: [String: FindMyKey](), { $0[$1.hashedKey.base64EncodedString()] = $1 })
        
        let accessQueue = DispatchQueue(label: "threadSafeAccess", qos: .userInitiated, attributes: .concurrent, autoreleaseFrequency: .workItem, target: nil)
        var decryptedReports = [FindMyLocationReport](repeating: FindMyLocationReport(lat: 0, lng: 0, acc: 0, dP: Date(), t: Date(), c: 0, id: ""), count: reps.count)
        DispatchQueue.concurrentPerform(iterations: reps.count) { (reportIdx) in
            let report = reps[reportIdx]
            guard let key = keyMap[report.id] else { return }
            do {
                let locationReport = try DecryptReports.decrypt(report: report, with: key)
                accessQueue.async(flags: .barrier) {
                    decryptedReports[reportIdx] = locationReport
                }
            } catch {
                return
            }
        }
        
        accessQueue.sync {
            self.decryptedReports = decryptedReports
        }
        completion()
        
    }
    
    func decodeReports(with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {
        
        var reportMap = [String: [FindMyReport]]()
        reps.forEach{ (reportMap[hexString(key: self.keys[$0.id]!), default:[]]).append($0) }
        for rep in reps {
            print(rep)
        }
        reps.forEach{ (reportMap[hexString(key: Array(self.keys[$0.id]!)), default:[]]).append($0) }
        var seenKeys = [String]()
        reportMap.keys.forEach{ seenKeys.append($0) }
        seenKeys.sort()
        
        var homeDirURL = FileManager.default.homeDirectoryForCurrentUser
        var fileURL = homeDirURL.appendingPathComponent("reports-dictionary.json")
        do {
            let jsonData = try JSONEncoder().encode(reportMap)
            try jsonData.write(to: fileURL)
        } catch {
            print("Could not find file to write to")
        }
        
        homeDirURL = FileManager.default.homeDirectoryForCurrentUser
        fileURL = homeDirURL.appendingPathComponent("reports-decrypted.json")
        do {
            let jsonData = try JSONEncoder().encode(self.decryptedReports)
            try jsonData.write(to: fileURL)
        } catch {
            print("Could not find file to write to")
        }
        
    }
}


struct FindMyControllerKey: EnvironmentKey {
    static var defaultValue: FindMyController = .shared
}

extension EnvironmentValues {
    var findMyController: FindMyController {
        get { self[FindMyControllerKey.self] }
        set { self[FindMyControllerKey.self] = newValue }
    }
}
enum FindMyErrors: Error {
    case decodingPlistFailed(message: String)
    case objectReleased
}

enum KeyError: Error {
    case keyGenerationFailed
    case keyDerivationFailed
}
