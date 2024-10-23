# Crypto API

This Project is a Student Project for the course "*Computer Networks*" at Hanyang University, Seoul, South Korea. The project is for education purpose. It may contain errors **It is not intended for professional use**. 

This repository contains demo code for interacting with the Kraken API, with examples to **check account balance** and **place sell orders**.
It aims to introduce to encryption keys and HTTP protocol, sending a properly formatted packet.

The project is divided into two parts, one in python the other in C++. The 2 project's codes do (mostly) the same things:

- **CryptoAPI_PY**: A Python project
- **CryptoAPI_CPP_CMake**: A C++ project using CMake to build the project. Developed in Visual Studio 2022, compatible with Linux/macOS.

--- 

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Acknowledgments](#acknowledgments)

## Features
This repository demonstrates how to interact with the Kraken cryptocurrency exchange API to:
1. **Check account balance**.
2. **Place a sell order**.
3. **Test the limit rate of the API** only in Python.
   
The code is provided in Two different programming language:
- A **Python** version.
- A **C++ version** using CMake.

---

## Installation

### Clone the Repository

```bash
git clone https://github.com/TheHardy04/CryptoAPI.git
cd CryptoAPI
````

### Set up Kraken API Key

#### 1. Create a Kraken account
Create a Kraken account on [Kraken's website](https://www.kraken.com/c) (no need to check ID)

#### 2. Create API Key
Create your API Key in your [account's settings](https://www.kraken.com/c/account-settings/api) choosing the options :
- Query funds
- Create and modify orders

*(Those are the permissions you need to run the demo code)*

#### 3. Add your API public and private key to your envrionment
- Windows
```cmd
set KRAKEN_API_KEY="YourPublicAPIKey"
set KRAKEN_API_SECRET="YourPrivateAPIKey"
```
- Linux/MacOS
```bash
export KRAKEN_API_KEY="YourPublicAPIKey"
export KRAKEN_API_SECRET="YourPrivateAPIKey"
```

---

## Usage

### Python Project (CryptoAPI_PY)

#### Prerequisites
- Python 3.10 or higher installed on your system.
#### Running the Python Script
```bash
cd CryptoAPI_PY
python main.py 
```
You can test the limits of the API operations by adding `rate` or `test` as an argument when running the code :
 ```bash
cd CryptoAPI_PY
python main.py rate
```

---

### C++ Project for Visual Studio (CryptoAPI_CPP)
#### Prerequisites
- Windows OS
- Visual Studio with C++ and Cmake development environment set up.
#### Running the C++ Project in Visual Studio (Windows only)
1. Open Visual Studio and load the project directory. Visual Studio should automatically detect the `CmakeList.txt` file and start configure the project
2. Run the project from Visual Studio pressing **F5**  (or selecting Debug > Start Debugging).

--- 

### C++ Project on Linux/MacOS (CryptoAPI_CPP_CMake)
#### Prerequisites
- CMake installed on your system.
- GCC/Clang for Linux/macOS.
#### Dependencies
- Debian/Ubuntu
```bash
sudo apt update
sudo apt install libcurl4-openssl-dev libssl-dev
```

- Fedora
```bash
sudo dnf install libcurl-devel openssl-devel
```

- MacOS
```bash
brew install curl openssl
```
#### Building 
1. Navigate to the CryptoAPI_CPP_CMake folder:
```bash
cd CryptoAPI_CPP_CMAKE
```
2. Create a `build` directory and navigate to it
```bash
mkdir build && cd build
```
3. Run CMake to configure the project:
```bash
cmake ..
```
4. Build the projec
```bash
make
```
5. Run the  executable
```bash
./CryptoAPI_CPP
```

---

## Acknowledgments
- [Hanyang University](http://www.hanyang.ac.kr/)
- Profesor : 원영준
