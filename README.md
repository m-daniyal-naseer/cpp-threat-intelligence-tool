# C++ Threat Intelligence Tool

A console-based threat intelligence tool built in C++ that checks IP addresses against three real security APIs and returns a combined threat verdict.

## What it does

Given an IP address, the tool:
- Validates the IP format
- Checks abuse reports via **AbuseIPDB**
- Retrieves location/ISP info via **IPStack**
- Scans against 90+ security engines via **VirusTotal**
- Combines all three results into a single **HIGH / MEDIUM / LOW** verdict
- Stores results in memory (vector) and persists them to a local file

## Example output

```
=====================================
     THREAT INTELLIGENCE SYSTEM
=====================================
1. Add Threat
2. Display All
3. Search by IP
4. Delete Threat
5. Filter by Level
7. Exit
=====================================
Enter choice: 1

--- Add New Threat ---
Enter IP: 185.220.101.45
----------------------------
Abuse Score: 100/100
Country: DE
Total Reports: 57
----------------------------
Country: Germany
City: Bonn
Zip: 53111
ISP: Stiftung Erneuerbare Freiheit
----------------------------
VirusTotal Results:
Malicious: 16
Suspicious: 3
Harmless: 42
----------------------------
Final Verdict: HIGH
------------------END OF REPORT----------------------
```

## Features

- Menu-driven CRUD system — add, display, search, delete, and filter threats
- IP format validation (rejects malformed input before hitting any API)
- Cross-references 3 independent threat intelligence sources
- Graceful error handling (try/catch around all JSON parsing — won't crash on empty/malformed API responses)
- Detects and skips private IP ranges (no point querying public APIs for local addresses)
- Saves results to a local file for persistence between runs

## Tech stack

- **C++** — core logic, OOP (`Threat` class), STL vectors
- **libcurl** — HTTP requests to external APIs
- **nlohmann/json** — JSON parsing
- **APIs:** [AbuseIPDB](https://www.abuseipdb.com/), [IPStack](https://ipstack.com/), [VirusTotal](https://www.virustotal.com/)

## Setup (Windows / MSYS2)

This project was built and tested using MSYS2 MinGW x64 on Windows.

1. Install [MSYS2](https://www.msys2.org/)
2. Open **MSYS2 MinGW x64** terminal and install dependencies:
   ```bash
   pacman -S mingw-w64-x86_64-toolchain
   pacman -S mingw-w64-x86_64-curl
   pacman -S mingw-w64-x86_64-nlohmann-json
   ```
3. Add your own API keys in `day1.cpp` (get free keys from AbuseIPDB, IPStack, and VirusTotal):
   ```cpp
   string apikey = "YOUR_API_KEY_HERE";
   ```
4. Compile and run (from MSYS2 MinGW x64 terminal, in the project folder):
   ```bash
   g++ -o main day1.cpp -lcurl
   ./main
   ```

> Note: this must be compiled from the **MSYS2 MinGW x64** terminal, not a regular Windows terminal or older MinGW installs — libcurl and nlohmann/json are linked through the MSYS2 toolchain.

## What I learned building this

This was my first project working with real-world APIs in C++. Along the way I had to:
- Set up a proper C++/curl build environment from scratch (MinGW vs MSYS2 vs MSYS — these are not the same thing)
- Debug linker errors (`ld returned 5 exit status`) caused by missing library paths
- Handle inconsistent/empty API responses without crashing the program (try/catch around JSON parsing)
- Understand HTTP headers and authentication patterns across 3 different APIs (URL params vs custom headers)
- Combine multiple independent data sources into one coherent decision

## Future improvements

- Case-insensitive search/filter
- Stricter private-IP range detection
- URL and email reputation checking (Google Safe Browsing, AbstractAPI)
- Possible web-based front end

## Disclaimer

This is a learning project. API keys are not included — get your own free keys from the respective providers and add them locally before running.
