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

  @Published var modemID: UInt32 = 0
  @Published var chunkLength: UInt32 = 8

  @Published var startKey: [UInt8] = [0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26]

  func clearMessages() {
     self.messages = [UInt32: Message]()
  }

  func xorArrays(a: [UInt8], b: [UInt8]) -> [UInt8] {
    var result = [UInt8]()
    if (a.count == b.count) {
      for i in 0..<a.count {
          result.append(a[i] ^ b[i])
      }
    } else if (a.count < b.count) {
      for i in 0..<a.count {
          result.append(a[i] ^ b[i])
      }
      for i in a.count..<b.count {
          result.append(b[i])
      }
    } else if (a.count > b.count) {
      for i in 0..<b.count {
//        print("a: \(a[i])")
//        print("b: \(b[i])")
//        print("i: \(i)")
//        print("result: \(result[i])")
          result.append(a[i] ^ b[i])
      }
      for i in b.count..<a.count {
          result.append(a[i])
      }
    }
    return result
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
    
    let static_prefix: [UInt8] = [0xba, 0xbe]

    var m = self.messages[messageID]!
    let chunkLength = m.chunkLength
    let decoded: [UInt8]
    if m.decodedBytes != nil{
        decoded = m.decodedBytes!
    } else{
        decoded = [0]
    }
//    let decoded: [UInt8] = m.decodedBytes!
    let recovered: [UInt8] = xorArrays(a: startKey, b: decoded)
    let adv_key_prefix = static_prefix + byteArray(from: m.modemID)

    for val in 0..<Int(pow(Double(2), Double(chunkLength))) {
      var validKeyCounter: UInt16 = 0
      var adv_key = adv_key_prefix
      var offsetVal = byteArray(from: val << (chunkLength * startChunk))

      repeat {
        adv_key += byteArray(from: validKeyCounter) + xorArrays(a: recovered, b: offsetVal)
        validKeyCounter += 1
        print("==== Testing key")
      } while (BoringSSL.isPublicKeyValid(Data(adv_key)) == 0)

      print("Found valid pub key on \(validKeyCounter). try")
      let k = DataEncodingKey(index: UInt32(startChunk), value: UInt8(val), advertisedKey: adv_key, hashedKey: SHA256.hash(data: adv_key).data)
      m.keys.append(k)
      print(Data(adv_key).base64EncodedString())
    }

    m.fetchedChunks += 1
    self.messages[UInt32(messageID)] = m
    // Includes async fetch if finished, otherwise fetches more bits
    self.fetchReports(for: messageID, with: searchPartyToken, completion: completion)
  }

  func fetchMessage(
    for modemID: UInt32, message messageID: UInt32, chunk chunkLength: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void
    ) {
    
    self.modemID = modemID
    self.chunkLength = chunkLength
    let start_index: UInt32 = 0
    let message_finished = false;
        let m = Message(modemID: modemID, messageID: UInt32(messageID), chunkLength: chunkLength)
    self.messages[messageID] = m
 
    fetchBitsUntilEnd(for: modemID, message: messageID, startChunk: start_index, with: searchPartyToken, completion: completion);
  }



  func fetchReports(for messageID: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {

    DispatchQueue.global(qos: .background).async {
      let fetchReportGroup = DispatchGroup()
      let fetcher = ReportsFetcher()

        fetchReportGroup.enter()

        let keys = self.messages[messageID]!.keys
        let keyHashes = keys.map({ $0.hashedKey.base64EncodedString() })

        // 21 days reduced to 1 day
        let duration: Double = (24 * 60 * 60) * 1
        let startDate = Date() - duration

        fetcher.query(
          forHashes: keyHashes,
          start: startDate,
          duration: duration,
          searchPartyToken: searchPartyToken
        ) { jd in
          guard let jsonData = jd else {
            fetchReportGroup.leave()
            return
          }

          do {
            // Decode the report
            let report = try JSONDecoder().decode(FindMyReportResults.self, from: jsonData)
            self.messages[UInt32(messageID)]!.reports += report.results
          } catch {
            print("Failed with error \(error)")
            self.messages[UInt32(messageID)]!.reports = []
          }
          fetchReportGroup.leave()
        }

      // Completion Handler
      fetchReportGroup.notify(queue: .main) {
        print("Finished loading the reports. Now decode them")

        // Export the reports to the desktop
        var reports = [FindMyReport]()
        for (_, message) in self.messages {
          for report in message.reports {
            reports.append(report)
          }
        }
        DispatchQueue.main.async {
            self.decodeReports(messageID: messageID, with: searchPartyToken) { _ in completion(nil) }
          }

        }
      }
    }

  

    func decodeReports(messageID: UInt32, with searchPartyToken: Data, completion: @escaping (Error?) -> Void) {
      print("Decoding reports")

      // Iterate over all messages
      var message = messages[messageID]

      // Map the keys in a dictionary for faster access
      let reports = message!.reports
      let keyMap = message!.keys.reduce(
        into: [String: DataEncodingKey](), { $0[$1.hashedKey.base64EncodedString()] = $1 })

      var reportMap = [String: Int]()
      reports.forEach{ reportMap[$0.id, default:0] += 1 }

      //print(keyMap)
      //print(reportMap)
      var result = [UInt32: UInt8]()
      var earlyExit = false
      var chunkLength = message!.chunkLength
      for (report_id, count) in reportMap {
        guard let k = keyMap[report_id] else { print("FATAL ERROR"); return; }
        result[k.index] = k.value
          print("Bit \(k.index): \(k.value) (\(count))")
      }
      
      var workingBitStr = message!.workingBitStr!
      var decodedBits = message!.decodedBits!
      var decodedStr = message!.decodedStr!
      var chunk_valid = 1
      var chunk_completely_invalid = 1
      if result.keys.max() == nil { print("No reports found"); completion(nil); return }
      let val = result[message!.fetchedChunks]!
      if val == nil {
          chunk_valid = 0
          workingBitStr += "?"
      } else {
          chunk_completely_invalid = 0
          var bitStr = String(val, radix: 2)
          var bitStrPadded = pad(string: bitStr, toSize: Int(chunkLength))
          workingBitStr += bitStrPadded
          decodedBits = bitStr + decodedBits
          
      }
      let (quotient, remainder) = workingBitStr.count.quotientAndRemainder(dividingBy: 8)
      if (remainder == 7) { // End of byte
        if chunk_completely_invalid == 1 {
          earlyExit = true
        }
        if chunk_valid == 1 {
          print("Fetched a full byte")
          let valid_byte = UInt8(strtoul(String(workingBitStr.prefix(8)), nil, 2))
          workingBitStr = String(workingBitStr.dropFirst(8))
          print("Full byte \(valid_byte)")
          let str_byte = String(bytes: [valid_byte], encoding: .utf8)
          decodedStr += str_byte ?? "?"
        }
        else {
          print("No full byte")
          decodedStr += "?"
        }
        chunk_valid = 1
        chunk_completely_invalid = 1
      }
      
      message?.workingBitStr = workingBitStr
      message?.decodedBits = decodedBits
      message?.decodedBytes = byteArray(from: Int(strtoul(decodedBits, nil, 2)))
      message?.decodedStr = decodedStr

      print("Result bytestring: \(decodedStr)")

      self.messages[messageID] = message
      if earlyExit {
          print("Fetched a fully invalid byte. Message probably ended.")
          completion(nil)
          return
      }
      // Not finished yet -> Next round
      print("Haven't found end byte yet. Starting with bit \(result.keys.max) now")
      fetchBitsUntilEnd(for: modemID, message: messageID, startChunk: UInt32(result.keys.max()!), with: searchPartyToken, completion: completion); // remove bitCount magic value   
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
}
