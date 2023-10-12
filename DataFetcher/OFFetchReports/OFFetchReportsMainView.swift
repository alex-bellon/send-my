//
//  OpenHaystack – Tracking personal Bluetooth devices via Apple's Find My network
//
//  Copyright © 2021 Secure Mobile Networking Lab (SEEMOO)
//  Copyright © 2021 The Open Wireless Link Project
//
//  SPDX-License-Identifier: AGPL-3.0-only
//

import SwiftUI

struct OFFetchReportsMainView: View {
    
    @Environment(\.findMyController) var findMyController
    
    @State var error: Error?
    @State var genKey = false
    @State var loading = false
    @State var retrieveReports = false
    
    @State var searchPartyToken: Data?
    @State var searchPartyTokenString: String = ""
    
    var mainView: some View {
        VStack {
            Spacer()
            Text("Would you like to generate keys or retreive reports?")
            HStack {
                Button(
                    action: {
                        self.findMyController.generatePublicKeys()
                        self.genKey = true
                    },
                    label: {
                        Text("Generate keys")
                    })
                Button(
                    action: {
                        self.loading = true
                        self.queryForReports()
                    },
                    label: {
                        Text("Retrieve reports")
                    })
            }
            Spacer()
        }
    }
    
    var genKeyView: some View {
        VStack {
            Spacer()
            Text("Keys generated and written to ~/keypairs.txt")
            HStack {
                Spacer()
                Button(action: {
                    self.genKey = false
                }, label: {
                    Text("Return to main menu")
                })
                Spacer()
            }
            Spacer()
        }
    }
    
    var retrieveReportsView: some View {
        VStack {
            Spacer()
            Text("Retrieved reports, written to ~/reports-dictionary.json and ~/reports-decrypted.json")
            HStack {
                Spacer()
                Button(action: {
                    self.retrieveReports = false
                }, label: {
                    Text("Return to main menu")
                })
                Spacer()
            }
            Spacer()
        }
    }
    
    var loadingView: some View {
        VStack {
            Text("Retrieving reports...")
                .font(Font.system(size: 32, weight: .bold, design: .default))
                .padding()
        }
    }
    
    var body: some View {
        GeometryReader { geo in
            if self.loading {
                self.loadingView
            } else if self.genKey {
                self.genKeyView
            } else if self.retrieveReports {
                self.retrieveReportsView
            } else {
                self.mainView
                    .frame(width: geo.size.width, height: geo.size.height)
            }
        }
    }
    
    struct ContentView_Previews: PreviewProvider {
        static var previews: some View {
            OFFetchReportsMainView()
        }
    }
    
    func queryForReports() {
        AnisetteDataManager.shared.requestAnisetteData { result in
            switch result {
            case .failure(_):
                print("AnsietteDataManager failed.")
            case .success(let accountData):
                
                guard let token = accountData.searchPartyToken,
                      token.isEmpty == false
                else {
                    print("Fail token")
                    return
                }
                print("Fetching data")
                print(token)
                self.findMyController.retreiveForPredeterminedKeys(with: token,
                                                                   completion: { error in
                    // Check if an error occurred
                    guard error == nil else {
                        print("An error occured. Not showing data.")
                        self.error = error
                        return
                    }
                    
                    // Show data view
                    self.loading = false
                    self.retrieveReports = true
                    
                })
            }
        }
    }
}
