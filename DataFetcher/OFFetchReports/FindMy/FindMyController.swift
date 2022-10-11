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

  //@Published var startKey: [UInt8] = [0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26, 0x7a, 0x6a, 0x10, 0x26]
  @Published var startKey: [UInt8] = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]

  func clearMessages() {
     self.messages = [UInt32: Message]()
  }

  func xorArrays(a: [UInt8], b: [UInt8]) -> [UInt8] {
    var result = [UInt8]()
    if (a.count == b.count) {
      for i in 0..<a.count {
          result.insert(a[i] ^ b[i], at: 0)
      }
    } else if (a.count < b.count) {
      for i in 0..<a.count {
          result.insert(a[a.count - i - 1] ^ b[b.count - i - 1], at: 0)
      }
      for i in a.count..<b.count {
          result.insert(b[b.count - i - 1], at: 0)
      }
    } else if (a.count > b.count) {
      for i in 0..<b.count {
          result.insert(a[a.count - i - 1] ^ b[b.count - i - 1], at: 0)
      }
      for i in b.count..<a.count {
          result.insert(a[a.count - i - 1], at: 0)
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
    //m.keys = []
    let chunkLength = m.chunkLength
    let decoded: [UInt8]

    if m.decodedBytes != nil{
        decoded = m.decodedBytes!
    } else {
        decoded = [0x0]
    }

    let recovered: [UInt8] = xorArrays(a: startKey, b: decoded)
        
    for val in 0..<Int(pow(Double(2), Double(chunkLength))) {
      var validKeyCounter: UInt16 = 0
      var adv_key = [UInt8]()
//      print(chunkLength)
//      print(startChunk)
//      print(val)
//      var offsetVal = byteArray(from: val << (chunkLength * startChunk))
        var offsetValLen = chunkLength * (startChunk + 1)
        var offsetValChunks = (offsetValLen / 8)
        var leftover = (offsetValLen) % 8
        if (leftover) != 0 { offsetValChunks += 1 }
        var offsetVal = Array(repeating: UInt8(0x0), count: Int(offsetValChunks))
        
        let mask = UInt8(1 << chunkLength)
        if (leftover == 0) {
            offsetVal[0] = UInt8(val) << (8 - chunkLength)
        } else if (leftover < chunkLength) {
            offsetVal[1] = UInt8(val) << (8 - (chunkLength - leftover))
            offsetVal[0] = UInt8(val) >> (chunkLength - leftover)
        } else {
            offsetVal[0] = UInt8(val) << (leftover - chunkLength)
        }
        
        //print("offsetVal: " + String(describing: offsetVal))
        //print("recovered: " + String(describing: recovered))

      repeat {
        adv_key = static_prefix + byteArray(from: m.modemID)
        adv_key += byteArray(from: validKeyCounter) + xorArrays(a: recovered, b: offsetVal)
        validKeyCounter += 1
        //print("==== Testing key")
        //print("Valid Key Counter: \(validKeyCounter)")
        //var key_hex = String(format:"%02X", adv_key[0])
        //for i in 1..<adv_key.count{
        //    key_hex += " " + String(format:"%02X", adv_key[i])
        //}
        //key_hex += "\n"
        //print("Attempted key: \(key_hex)")
        //print()
      } while (BoringSSL.isPublicKeyValid(Data(adv_key)) == 0 && validKeyCounter < UInt16.max)

      var key_hex = String(format:"%02X", adv_key[0])
      for i in 1..<adv_key.count{
          key_hex += " " + String(format:"%02X", adv_key[i])
      }
      //key_hex += "\n"
      print("Valid key: \(key_hex)")
      //print("Found valid pub key on \(validKeyCounter). try")
      let k = DataEncodingKey(index: UInt32(startChunk), value: UInt8(val), advertisedKey: adv_key, hashedKey: SHA256.hash(data: adv_key).data)
      m.keys.append(k)
//      print(Data(adv_key).base64EncodedString())
    }

    m.fetchedChunks += 1
    print(m.fetchedChunks)
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
        let chunkLength = message!.chunkLength
      for (report_id, count) in reportMap {
        guard let k = keyMap[report_id] else { print("FATAL ERROR"); return; }
          if (result[k.index] != nil) {
              let cLen = message!.chunkLength
              let leftover = ((k.index + 1) * cLen) % 8
              var startVal: UInt8
              let mask = UInt8(1 << cLen)
              if (leftover == 0) {
                  startVal = (startKey[(Int(((k.index + 1) * cLen)) / 8) - 1] >> (8 - cLen)) & mask
              } else if (leftover < cLen) {
                  let val_lo = startKey[Int(((k.index + 1) * cLen)) / 8] << (cLen - leftover)
                  let val_hi = startKey[(Int(((k.index + 1) * cLen)) / 8) - 1] >> leftover
                  startVal = (val_lo ^ val_hi) & mask
              } else {
                  startVal = (startKey[(Int(((k.index + 1) * cLen)) / 8) - 1] >> (leftover - cLen)) & mask
              }
              
              if (startVal != k.value) {
                  result[k.index] = k.value
              }
          } else {
              result[k.index] = k.value
          }
          
        
          print("Bit \(k.index): \(k.value) (\(count))")
      }
      
      var workingBitStr: String
      var decodedBits : String
      var decodedStr: String
        
      if message!.workingBitStr != nil {
          workingBitStr  = message!.workingBitStr!
      }
      else {
          workingBitStr = ""
      }
        
      if message!.decodedBits != nil {
          decodedBits  = message!.decodedBits!
      }
      else {
          decodedBits = ""
      }
        
      if message!.decodedStr != nil {
          decodedStr  = message!.decodedStr!
      }
      else {
          decodedStr = ""
      }
        
//      var workingBitStr = message!.workingBitStr!
//      var decodedBits = message!.decodedBits!
//      var decodedStr = message!.decodedStr!
      var chunk_valid = 1
      var chunk_completely_invalid = 1
      if result.keys.max() == nil { print("No reports found"); completion(nil); return }
    
//      print(result)
      print(message!.fetchedChunks - 1)
      let val = result[message!.fetchedChunks - 1]
      if val == nil {
          chunk_valid = 0
          workingBitStr += "?"
      } else {
          chunk_completely_invalid = 0
          var bitStr = String(val!, radix: 2)
          var bitStrPadded = pad(string: bitStr, toSize: Int(chunkLength))
          workingBitStr = bitStrPadded + workingBitStr
          print("Working bit string: " + workingBitStr)
          print("Old decoded bits: " + decodedBits)
          decodedBits = bitStrPadded + decodedBits
          print("New decoded bits: " + decodedBits)
      }
      //let (quotient, remainder) = workingBitStr.count.quotientAndRemainder(dividingBy: 8)
        if (workingBitStr.count >  8) { // End of byte
        if chunk_completely_invalid == 1 {
          print("Chunk invalid")
          earlyExit = true
        }
        if chunk_valid == 1 {
          print("Fetched a full byte")
          let valid_byte = UInt8(strtoul(String(workingBitStr.suffix(8)), nil, 2))
            if (valid_byte == 0) {
                earlyExit = true
            } else {
          workingBitStr = String(workingBitStr.dropLast(8))
          print("Full byte \(valid_byte)")
          let str_byte = String(bytes: [valid_byte], encoding: .utf8)
          decodedStr = (str_byte ?? "?") + decodedStr
            }
        }
        else {
          print("No full byte")
          //decodedStr = "?" + decodedStr
        }
        chunk_valid = 1
        chunk_completely_invalid = 1
      }
      
      message?.workingBitStr = workingBitStr
      message?.decodedBits = decodedBits
    
      var decodedBytes = [UInt8]()
        
        print(decodedBits)

        while decodedBits.count % 8 != 0 {
            decodedBits = "0" + decodedBits
        }
        print(decodedBits)
        
        var leng = Int(decodedBits.count / 8)
        for i in 0..<leng {
            var substr = String(decodedBits.dropFirst(i * 8).prefix(8))
            var byte = Int(strtoul(substr, nil, 2))
            decodedBytes.append(UInt8(byte))
        }
    
      message?.decodedBytes = decodedBytes
      message?.decodedStr = decodedStr
        
      print("Result bytestring: \(decodedStr)")

      self.messages[messageID] = message
      if earlyExit {
          print("Fetched a fully invalid byte. Message probably ended.")
          completion(nil)
          return
      }
      // Not finished yet -> Next round
      print("Haven't found end byte yet. Starting with bit \(result.keys.max()! + 1) now")
      fetchBitsUntilEnd(for: modemID, message: messageID, startChunk: UInt32(result.keys.max()! + 1), with: searchPartyToken, completion: completion); // remove bitCount magic value
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
