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
    
    var modemID: UInt32 = 0xd3ad1004
    var count: UInt16 = 5000
        
    func clearMessages() {
        return;
    }
    
    func pad(string: String, toSize: Int) -> String {
        var padded = string
        for _ in 0..<(toSize - string.count) {
            padded = "0" + padded
        }
        return padded
    }
    
    
    func fetchBitsUntilEnd(
        for modemID: UInt32, message messageID: UInt32, startChunk: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void
    ) {

        for i in 0..<2515 {
            let key = BoringSSL.generateNewPrivateKey()
            var publicKey = BoringSSL.derivePublicKey(fromPrivateKey: key!)
            publicKey = publicKey!.dropFirst()
            print(hexString(key: key!) + "," + hexString(key: publicKey!))
        }

        return
        
        var experiment = true
    //  NOTE: start and end indices are
        
        if experiment {
            
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
                        if pub == "" {
                            continue
                        }
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
                    self.fetchReports(for: messageID, with: searchPartyToken, completion: completion)
                }
                catch {print("Error: could not read file")}
            }
            return
        }
        
        var m = self.messages[messageID]!
        
        self.messages[UInt32(messageID)] = m
        self.fetchReports(for: messageID, with: searchPartyToken, completion: completion)
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
    
    func fetchMessage(
        for modemID: UInt32, message messageID: UInt32, chunk chunkLength: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void
    ) {
        
        let start_index: UInt32 = 0
        let m = Message(modemID: modemID, messageID: UInt32(messageID), chunkLength: chunkLength)
        self.messages[messageID] = m
        
        fetchBitsUntilEnd(for: modemID, message: messageID, startChunk: start_index, with: searchPartyToken, completion: completion);
    }
    
    func calculateKeys(num: UInt16, modem_id: UInt32) -> [Data] {
        var result = [Data]()
        let prefix: [UInt8] = [0xba, 0xbe]
        let pad: [UInt8] = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        for count in 0...num {
            var tweak: UInt16 = 0
            var key = [UInt8]()
            repeat {
                key = prefix + byteArray(from: modem_id) + byteArray(from: tweak) + pad + byteArray(from: count)
                tweak += 1
            } while (BoringSSL.isPublicKeyValid(Data(key)) == 0 && tweak < UInt16.max)
            print(hexString(key: key))
            var hash = SHA256.hash(data: key).data
            var b64 = hash.base64EncodedString()
            self.keys[b64] = key
            result.append(hash)
        }
        return result
    }
    
    func fetchReports(for messageID: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {
        
        DispatchQueue.global(qos: .background).async {
            let fetchReportGroup = DispatchGroup()
            let fetcher = ReportsFetcher()
            
            fetchReportGroup.enter()
            
            //self.keyHashes = self.calculateKeys(num: self.count, modem_id: self.modemID) // TODO: actually take this number and modem ID in through UI
            
            
            var keyEncoded = self.keyHashes.map({ $0.base64EncodedString() })
//            for key in self.findMyKeys {
//                print(key)
//            }
            //print(keyEncoded.count)
            
            
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
                    self.messages[UInt32(messageID)]!.reports += report.results
                    self.reps += report.results
                    //print(report)
                } catch {
                    print("Failed with error \(error)")
                    self.messages[UInt32(messageID)]!.reports = []
                }
                fetchReportGroup.leave()
            }
            
            
            fetchReportGroup.notify(queue: .main) {
                print("Finished loading the reports. Now decrypt them")

                // Export the reports to the desktop
                var reports = [FindMyReport]()
                reports = self.reps

                #if EXPORT
                    if let encoded = try? JSONEncoder().encode(reports) {
                        let outputDirectory = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first!
                        try? encoded.write(to: outputDirectory.appendingPathComponent("reports.json"))
                    }
                #endif

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
            
            
            // Completion Handler
            fetchReportGroup.notify(queue: .main) {
                DispatchQueue.main.async {
                    self.decodeReports(messageID: messageID, with: searchPartyToken) { _ in completion(nil) }
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
                        // Decrypt the report
                        //print(reportIdx)
                        //print(report)
                        let locationReport = try DecryptReports.decrypt(report: report, with: key)
                        //print(locationReport)
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
    
    func decodeReports(messageID: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {
        //print("Decoding reports")
        
        var reportMap = [String: [FindMyReport]]()
        reps.forEach{ (reportMap[hexString(key: self.keys[$0.id]!), default:[]]).append($0) }
        for rep in reps {
            print(rep)
        }
        reps.forEach{ (reportMap[hexString(key: Array(self.keys[$0.id]!)), default:[]]).append($0) }
        //print(reps.count)
        var seenKeys = [String]()
        reportMap.keys.forEach{ seenKeys.append($0) }
        seenKeys.sort()
        //print(seenKeys)
        
        var homeDirURL = FileManager.default.homeDirectoryForCurrentUser
        var fileURL = homeDirURL.appendingPathComponent("git/LoRa-analysis/analysis/shipment/ble-data/dump.json")
        do {
            let jsonData = try JSONEncoder().encode(reportMap)
            //print(jsonData)
            try jsonData.write(to: fileURL)
        } catch {
            print("ruh roh raggy")
        }
        
        homeDirURL = FileManager.default.homeDirectoryForCurrentUser
        fileURL = homeDirURL.appendingPathComponent("git/LoRa-analysis/analysis/shipment/ble-data/gps-locs.json")
        do {
            //let jsonData = try JSONEncoder().encode(reportMap)
            let jsonData = try JSONEncoder().encode(self.decryptedReports)
            //print(jsonData)
            try jsonData.write(to: fileURL)
        } catch {
            print("ruh roh raggy")
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
