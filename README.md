# CVEchecker

A description of this package.
proba


        CVEchecker().getCVEs(package: "ios", after: "2019-01-01") { (cves, error) in
            if let error = error {
                // Handle error
                print("Error: \(error.localizedDescription)")
            } else if let cves = cves {
                // Use the array of CVEs returned by the function
                print("CVEs: \(cves)")
            }
        }
