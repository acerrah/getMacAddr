# GetMacAddr
A basic library to get mac addresses from any ip with the usage of raw sockets for linux. This is made for educational purposes but if you want to use it in production, why not.

## Prerequisites

- CMake (version 3.12 or higher)
- A C++ compiler (supporting C++17)

## Getting Started

1. Clone the repository:

    ```shell
    git clone https://github.com/acerrah/arppacket.git arppacket
    ```

2. Navigate to the project directory:

    ```shell
    cd arppacket
    ```

3. Create a build directory:

    ```shell
    mkdir build
    ```

4. Generate the build files using CMake:

    ```shell
    cmake -B build
    ```

5. Build the project:

    ```shell
    cd build
    make
    make install # optional if you want to install it to your local system
    ```

## Usage
    ```cpp
    arp_packet arp("wlan0"); // Create an arp packet object with your interface that is connected to internet
    unsigned char* mac = arp.get_mac_address("target_ip"); // Change target_ip with the ip you want to get mac address of
    ```
    
## Contributing

If you'd like to contribute to this project, please follow these steps:

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT license.
