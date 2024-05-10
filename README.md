# Email IOC Extractor
This Python script is designed to aid in email forensic analysis by extracting various components from email files such as IP addresses, URLs, headers, and attachments.

## Features:
- **IP Address Extraction**: Identifies and extracts IP addresses from the email content in defanged format.
- **URL Extraction**: Extracts URLs from the email content in defanged format.
- **Header Extraction**: Retrieves common useful email headers to aid in sender attribution.
- **Attachment Extraction**: Parses email attachments and provides details such as filename, MD5, SHA1, and SHA256 hashes.

## Additional Functionalities:
- **IP and URL Defanging**: Defangs IP addresses and URLs, making them safer for analysis.
- **IP Information Lookup**: Utilizes the `ipinfo.io` API to gather information about IP addresses, including city, region, country, and ISP.

## Requirements

```bash
pip3 install -r requirements.txt
```

## Usage
```bash
python3 eioc.py <file_path>
```

Example:
```bash
$ python3 eioc.py sample1.eml 
Extracted IP Addresses:
====================================
209[.]85[.]128[.]170 - Atlanta, Georgia, US, ISP: AS15169 Google LLC
10[.]13[.]153[.]59

Extracted URLs:
====================================
hxxps[://]drive[.]google[.]com/file/d/1sdzd_hr-_bEt_tJabjINZfvYiOvEJjSJ
hxxps[://]apply-submite[.]vercel[.]app/

Extracted Headers:
====================================
Date: Mon, 31 Oct 2022 11:53:21 +0300
Subject: [Action required] Verify your info to continue using your account
To: undisclosed-recipients:;
From: Ropo12g Gaming <jodykrier60@gmail.com>
Return-Path: jodykrier60@gmail.com
Message-ID: <CANEy_Dj91bGpyHqz1fkK81s=JK9HDxUgYmg+2doKL01ZwbJaSg@mail.gmail.com>
X-Sender-IP: 209.85.128.170
Authentication-Results: spf=pass (sender IP is 209.85.128.170)

Extracted Attachments:
====================================
Filename: 3spyWy0D.pdf
MD5: 42f1cb17cee1027608917094c3fe99b9
SHA1: 5c8d32e624ec8074e3b6e97f48b3839faeacd7ee
SHA256: 6bd89500da5666a9444d2cd9af7a1fe4c945ea9fb31562d97018fdb2799dbda3
```

## Compatibility:
This script is compatible with Python 3.x.

## Disclaimer:
This tool is intended for analysis and research purposes only. Usage should comply with applicable laws and regulations.

## Contributions:
Contributions, bug reports, and feature requests are welcome. Feel free to open an issue or submit a pull request on GitHub.

## License:
This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments:
Special thanks to [ipinfo.io](https://ipinfo.io) for providing IP geolocation data.
