# SGX Environment Setup

Setting up an SGX (Software Guard Extensions) environment involves installing the necessary tools, SDKs, and dependencies to develop and run SGX-enabled applications. Below is a step-by-step guide to set up the environment on both **Linux** and **Windows**:

---

### **1. Prerequisites**

- A CPU that supports Intel SGX (e.g., recent Intel processors).
- SGX must be enabled in the BIOS/UEFI settings.
- OS support:
    - **Linux**: Ubuntu, CentOS, or other supported distributions.
    - **Windows**: Windows 10 or later (Professional or Enterprise editions).

### **2. Hardware check**
To run SGX applications, a hardware with Intel SGX support is needed. You can check with this list of [supported hardware](https://github.com/ayeks/SGX-hardware). Note that you sometimes need to configure BIOS to enable SGX.

* You can check if SGX is enabled on you system with `test_sgx.c` in [SGX-hardware](https://github.com/ayeks/SGX-hardware). Just compile and run it, you will get a report.
```shell
# For Linux/gcc 13.1
gcc -Wl,--no-as-needed -Wall -Wextra -Wpedantic -masm=intel -o test-sgx -lcap cpuid.c rdmsr.c xsave.c vdso.c test-sgx.c
```

### **3. Setup for Linux Environment**

The subsequent instructions are applicable to Ubuntu 20.04. You can find the official [installation guides](https://download.01.org/intel-sgx/sgx-linux/2.17.1/docs/) for Intel SGX software on the 01.org website. Additionally, you may find guides for other OS versions and SGX versions at [Intel-sgx-docs](https://download.01.org/intel-sgx/).

#### Step 1: Install SGX Driver
```shell
wget https://download.01.org/intel-sgx/sgx-linux/2.17.1/distro/ubuntu20.04-server/sgx_linux_x64_driver_2.11.b6f5b4a.bin

sudo ./sgx_linux_x64_driver_2.11.b6f5b4a.bin

ls /dev/isgx 
```

#### Step2: Install SGX PSW
* Add the repository to your sources:
```shell
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
```

* Add the key to the list of trusted keys used by the apt to authenticate packages:
```shell
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
```

* Update the apt and install the packages:
```shell
sudo apt-get update
```

* Install launch service: 
```shell
sudo apt-get install libsgx-launch libsgx-urts 
``` 

* Install EPID-based attestation service: 
```shell
sudo apt-get install libsgx-epid libsgx-urts  
```

* Install algorithm agnostic attestation service: 
```shell
sudo apt-get install libsgx-quote-ex libsgx-urts
```

#### Step3: Install SGX SDK
```shell
wget https://download.01.org/intel-sgx/sgx-linux/2.17.1/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.17.101.1.bin

./sgx_linux_x64_sdk_2.17.101.1.bin

source /your_path/sgxsdk/environment
```

#### Step4: Verify and test your SGX Setup
 1. Compile a sample SGX project (available in the SDK: `/your_sdk_path/sgxsdk/SampleCode`).
 2. Run it in both hardware and simulation modes to verify SGX functionality.
    - **Simulation mode**: SGX programs can run on CPUs without SGX support.
    - **Hardware mode**: Requires an SGX-enabled processor and BIOS.
