
/// \brief TCP UDP scanner 
/// \author Samuel Kundrat
/// \date 2025
/// XML comments created by CHATGPT
/// pridat CHANGELOG.md


using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Linq;
using System;
using SharpPcap;
using System.Numerics;



namespace IPK_L4_Scanner{
    //class that holds values from parsing arguments
    public class ScannerArgs
    {
        public string Interface { get; set; }
        public List<int> TcpPorts { get; set; } = new List<int>();
        public List<int> UdpPorts { get; set; } = new List<int>();
        public int Timeout { get; set; } = 5000; // Default timeout: 5000ms
        public string Target { get; set; }
    }
    //class for argument parsing
    public class ArgumentParser
    {
        
        /// <summary>
        /// Parses the command-line arguments and returns an instance of <see cref="ScannerArgs"/> containing the parsed options.
        /// This method processes the arguments passed to the program, including flags for interface selection, target hostname/IP address,
        /// TCP/UDP ports to scan, and timeout settings. If the arguments are incorrect or incomplete, appropriate error messages are displayed,
        /// and the program exits.
        /// </summary>
        /// <param name="args">An array of strings representing the command-line arguments passed to the program.</param>
        /// <returns>A <see cref="ScannerArgs"/> object populated with the parsed values from the arguments.</returns>
        /// <remarks>
        /// The following flags and options are supported:
        /// - "-i" or "--interface" : Specifies the network interface to use (if no interface is provided, available interfaces will be printed).
        /// - "-t" or "--pt" : Specifies the TCP port ranges to scan.
        /// - "-u" or "--pu" : Specifies the UDP port ranges to scan.
        /// - "-w" or "--wait" : Specifies the timeout value (must be a positive integer).
        /// - Target (hostname or IP address) is expected to be provided as the last argument unless the interface flag is used.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown when an invalid argument is encountered.</exception>
        public static ScannerArgs Parse(string[] args)
        {
            // Check if no arguments or only interface flag
            if (args.Length == 0 || 
                (args.Length == 1 && (args[0] == "-i" || args[0] == "--interface")) ||
                (args.Length >= 2 && (args[0] == "-i" || args[0] == "--interface") && args[1].StartsWith("-")))
            {
                PrintInterfaces();
                Environment.Exit(0);
            }

            // Check for help flag
            foreach (var arg in args)
            {
                if (arg == "-h" || arg == "--help")
                {
                    PrintUsage();
                    Environment.Exit(0);
                }
            }

            var scannerArgs = new ScannerArgs();
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];

                if (arg == "-i" || arg == "--interface")
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        scannerArgs.Interface = args[++i];
                    }
                }
                else if (arg == "-t" || arg == "--pt")
                {
                    if (i + 1 < args.Length)
                    {
                        scannerArgs.TcpPorts = ParsePortRanges(args[++i]);
                    }
                }
                else if (arg == "-u" || arg == "--pu")
                {
                    if (i + 1 < args.Length)
                    {
                        scannerArgs.UdpPorts = ParsePortRanges(args[++i]);
                    }
                }
                else if (arg == "-w" || arg == "--wait")
                {
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int timeout))
                        {
                            if (timeout <= 0)
                            {
                                Console.Error.WriteLine("Error: Timeout must be a positive integer");
                                Environment.Exit(1);
                            }
                            scannerArgs.Timeout = timeout;
                        }
                        else
                        {
                            Console.Error.WriteLine("Error: Invalid timeout value");
                            Environment.Exit(1);
                        }
                    }
                }
                else if (!arg.StartsWith("-") && string.IsNullOrEmpty(scannerArgs.Target))
                {
                    // This is probably the target
                    scannerArgs.Target = arg;
                }
                else{
                    Console.Error.WriteLine($"Argument {arg} not supported");
                    Environment.Exit(1);
                }
            }

            // Validate arguments
            if (!string.IsNullOrEmpty(scannerArgs.Target) && 
                scannerArgs.TcpPorts.Count == 0 && scannerArgs.UdpPorts.Count == 0)
            {
                Console.Error.WriteLine("Error: No ports specified for scanning");
                Environment.Exit(1);
            }

            if ((scannerArgs.TcpPorts.Count > 0 || scannerArgs.UdpPorts.Count > 0) && 
                string.IsNullOrEmpty(scannerArgs.Target))
            {
                Console.Error.WriteLine("Error: Missing target hostname or IP address");
                Environment.Exit(1);
            }

            return scannerArgs;
        }

        /// <summary>
        /// Parses a comma-separated string of port ranges or individual ports into a list of integers.
        /// Each port range is specified as "startPort-endPort", and individual ports can be specified as integers.
        /// The method validates that the port numbers fall within the valid range (1 to 65535) and that the port ranges are properly formatted.
        /// If any invalid input is encountered, an error message is displayed, and the program exits.
        /// </summary>
        /// <param name="portRanges">A comma-separated string containing individual ports or port ranges (e.g., "80,443,1000-2000").</param>
        /// <returns>A list of integers representing the parsed port numbers.</returns>
        /// <remarks>
        /// The input string can contain both individual ports (e.g., "80", "443") and ranges (e.g., "1000-2000").
        ///
        /// The following validation is performed:
        /// - Port numbers must be between 1 and 65535.
        /// - A range must be specified in the format "startPort-endPort", where startPort <= endPort.
        /// - If the input is invalid, an error message is printed, and the program exits.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown when the input format is invalid or the port number is out of range.</exception>
        private static List<int> ParsePortRanges(string portRanges)
        {
            var result = new List<int>();
            var ranges = portRanges.Split(',');

            foreach (var range in ranges)
            {
                if (range.Contains('-'))
                {
                    var parts = range.Split('-');
                    if (parts.Length == 2)
                    {
                        if (int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                        {
                            if (start <= 0 || end > 65535 || start > end)
                            {
                                Console.Error.WriteLine($"Error: Invalid port range {range}. Port numbers must be between 1 and 65535");
                                Environment.Exit(1);
                            }

                            for (int port = start; port <= end; port++)
                            {
                                result.Add(port);
                            }
                        }
                        else
                        {
                            Console.Error.WriteLine($"Error: Invalid port range format {range}, use --help for more information");
                            Environment.Exit(1);
                        }
                    }else{
                        Console.Error.WriteLine($"Error: Invalid port range format {range}, use --help for more information");
                        Environment.Exit(1);
                    }
                }
                else
                {
                    // Handle single port like 80, 400, ...
                    if (int.TryParse(range, out int port))
                    {
                        if (port <= 0 || port > 65535)
                        {
                            Console.Error.WriteLine($"Error: Invalid port number {port}. Port numbers must be between 1 and 65535");
                            Environment.Exit(1);
                        }
                        result.Add(port);
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: Invalid port specification {range}");
                        Environment.Exit(1);
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Prints a list of available network interfaces on the local machine, including both IPv4 and IPv6 addresses.
        /// The method retrieves all network interfaces using the <see cref="NetworkInterface.GetAllNetworkInterfaces"/> method, 
        /// and for each interface, it prints the name and associated IP addresses (both unicast IPv4 and IPv6 addresses).
        /// If an error occurs while fetching the network interfaces or their properties, an error message is displayed.
        /// </summary>
        /// <remarks>
        /// The method retrieves all network interfaces on the system and for each one:
        /// - Displays the name of the interface (e.g., "Ethernet", "Wi-Fi", "Local Area Connection").
        /// - Displays the unicast IPv4 and IPv6 addresses associated with that interface (if available).
        /// The information is printed in a tabular format with each interface's name followed by its respective addresses.
        /// </remarks>
        /// <exception cref="Exception">Thrown if there is an error retrieving the network interfaces or their properties.</exception>
        private static void PrintInterfaces()
        {
            Console.WriteLine("Available network interfaces:");
            
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    Console.Write($"{nic.Name}\t");
                    
                    var addresses = new List<string>();
                    foreach (var unicastAddress in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (unicastAddress.Address.AddressFamily == AddressFamily.InterNetwork || 
                            unicastAddress.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            addresses.Add(unicastAddress.Address.ToString());
                        }
                    }
                    
                    Console.WriteLine(string.Join(", ", addresses));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error getting network interfaces: {ex.Message}");
            }
        }
        /// <summary>
        /// Parses the target IP address or hostname from the provided `ScannerArgs` and returns a dictionary of IP addresses.
        /// If the target is a valid IP address, it is added to the dictionary with a boolean flag indicating whether it is IPv4 (true) or IPv6 (false).
        /// If the target is a hostname, the method resolves it to a list of IP addresses and adds them to the dictionary with the same boolean flag.
        /// </summary>
        /// <param name="args">The scanner arguments that contain the target IP address or hostname to be parsed.</param>
        /// <returns>A dictionary where the keys are IP addresses (both IPv4 and IPv6) and the values are booleans indicating if the address is IPv4 (true) or IPv6 (false).</returns>
        /// <remarks>
        /// If the target is a valid IP address, the method directly adds it to the dictionary.
        /// If the target is a hostname, it resolves the hostname to its associated IP addresses using DNS.
        /// If an invalid IP address is provided, or if the hostname resolution fails, an error message is printed and the program exits.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown if the provided target is not a valid IP address or hostname, or if the resolution fails.</exception>
        public static Dictionary<IPAddress, bool> ipParse(ScannerArgs args)
        {
            Dictionary<IPAddress, bool> result = new Dictionary<IPAddress, bool>();
            
            if (IPAddress.TryParse(args.Target, out IPAddress address))
            {
                switch (address.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        result.Add(address, true);
                        break;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        result.Add(address, false);
                        break;
                    default:
                        Console.Error.WriteLine($"Error: Unsupported address family: {address.AddressFamily}");
                        Environment.Exit(1);
                        break;
                }
            }
            else
            {
                // HOST not ip as paramater
                try
                {
                    //gets IPs from DNS resolution
                    IPHostEntry hostEntry = Dns.GetHostEntry(args.Target);
                    //loop that adds IPs to list
                    foreach (var addr in hostEntry.AddressList)
                    {
                        bool isIPv4 = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
                        result.Add(addr, isIPv4);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error resolving hostname: {ex.Message}");
                }
            }
            
            return result;
        }

        /// <summary>
    /// Prints the usage instructions and options for the `ipk-l4-scan` program to the console.
    /// This method provides a detailed description of how to use the tool, including available command-line options,
    /// expected arguments, and example usage scenarios.
    /// </summary>
    /// <remarks>
    /// The method outputs the following:
    /// - A general description of the command-line syntax for the program, specifying the options and their expected formats.
    /// - A list of available options with explanations, such as the interface to use, port ranges for scanning, timeout settings, and how to display help.
    /// - Examples showing how to use the tool with different options.
    /// </remarks>
        private static void PrintUsage()
        {
            Console.WriteLine("Usage: ipk-l4-scan [-i interface | --interface interface] " +
                "[--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] " +
                "{-w timeout} [hostname | ip-address]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -h, --help\t\t\tShow this help message");
            Console.WriteLine("  -i, --interface INTERFACE\tSpecify network interface");
            Console.WriteLine("  -t, --pt PORT-RANGES\t\tSpecify TCP ports to scan (e.g., 22,80,443 or 1-1024)");
            Console.WriteLine("  -u, --pu PORT-RANGES\t\tSpecify UDP ports to scan (e.g., 53,67,68 or 1-1024)");
            Console.WriteLine("  -w, --wait TIMEOUT\t\tSpecify timeout in milliseconds (default: 5000)");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  ipk-l4-scan --interface eth0 -u 53,67 2001:67c:1220:809::93e5:917");
            Console.WriteLine("  ipk-l4-scan -i eth0 -w 1000 -t 80,443,8080 www.vutbr.cz");
        }
    }
    
    //class for TCP and UDP scanner
    public class Scanner{
        /// <summary>
        /// Sends a raw TCP or UDP packet to the specified IP address and port. The method selects whether to send a TCP or UDP packet based on the `isTcp` flag.
        /// For TCP, a SYN packet is created and sent. For UDP, an empty packet is sent to the target address and port.
        /// </summary>
        /// <param name="port">The destination port number to which the packet should be sent.</param>
        /// <param name="ipAddress">The destination IP address (either IPv4 or IPv6).</param>
        /// <param name="isIPv4">A boolean flag indicating whether the IP address is IPv4 (true) or IPv6 (false).</param>
        /// <param name="interfaceName">The name of the network interface to use for sending the packet (unused in this implementation, but can be useful in future extensions).</param>
        /// <param name="isTcp">A boolean flag indicating whether to send a TCP packet (true) or UDP packet (false).</param>
        /// <remarks>
        /// This method creates and sends a raw packet to the specified address and port. It uses a raw socket, so administrative privileges may be required.
        /// - For TCP packets, a SYN packet is generated and sent to the target address and port.
        /// - For UDP packets, an empty 1-byte UDP packet (0x00) is sent to the target address and port.
        /// </remarks>
        /// <exception cref="SocketException">Thrown if there is an error in socket creation or sending the packet.</exception>
        public static void sendPacket(int port, IPAddress ipAddress, bool isIPv4, string interfaceName, bool isTcp)
        {
            //Console.WriteLine($"Using interface: {interfaceName}");
            // TCP part
            if(isTcp){
                //makes TCP RAW socket 
                using (Socket socket = new Socket(
                    isIPv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6,
                    SocketType.Raw, 
                    ProtocolType.Tcp))
                {
                    try
                    {
                        //creates endpoint, 0 - OS choses the interface
                        IPEndPoint endPoint = new IPEndPoint(ipAddress, 0);
                       
                        // Creates SYN packed based on if its IPv4 or IPv6 address
                        byte[] packet = isIPv4 ? CreateTcpSynPacket4(ipAddress, port, interfaceName) : CreateTcpSynPacket6(ipAddress, port, interfaceName);
                        // Odoslanie SYN paketu
                        //Console.WriteLine("posielam packet:");
                       // PrintPacket(packet);

                       //sends SYN packet
                        socket.SendTo(packet, endPoint);
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine($"Error: {e.Message}");
                    }
                }
            // UDP part
            }else if(!isTcp){
                try
                {
                    //creates endpoint
                    IPEndPoint endPoint = new IPEndPoint(ipAddress, port);
                    //creates UDP socket
                    Socket udpSocket = new Socket(isIPv4 ? AddressFamily.InterNetwork :AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                    //empty udp packet
                    byte[] udpPacket = new byte[1] { 0x00 };
                    //sends packet
                    udpSocket.SendTo(udpPacket, endPoint);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine($"Error: {e.Message}");
                }
                
            }
        }

        /// <summary>
        /// Starts a packet capture on the specified network interface using SharpPcap. The method selects the network interface based on the provided name,
        /// opens the device in promiscuous mode, and begins capturing packets. It also sets up an event handler to process captured packets.
        /// </summary>
        /// <param name="interfaceName">The name of the network interface to start scanning on.</param>
        /// <returns>An instance of the ICaptureDevice representing the selected network interface used for capturing packets.</returns>
        /// <exception cref="Exception">Throws an exception if no devices are found or if the specified interface name does not exist.</exception>
        /// <remarks>
        /// This method assumes that SharpPcap is correctly installed and configured. It listens for incoming packets on the selected interface and triggers the
        /// provided event handler (`device_OnPacketArrival`) when a packet is captured.
        /// </remarks>
        public static ICaptureDevice startScan(string interfaceName)
        {
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            if(devices.Count < 1)
            {
                Console.Error.WriteLine("No devices were found on this machine");
                    Environment.Exit(1);
            }
            //gets first interface with name based on interfaceName parameter
            var selectedDevice = devices.FirstOrDefault(dev => dev.Name == interfaceName);
            if(selectedDevice == null)
            {
                Console.Error.WriteLine($"No device found with the name: {interfaceName}");
                    Environment.Exit(1);
            }
            selectedDevice.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

            //opens port for capture
            selectedDevice.Open(DeviceModes.Promiscuous);
            
            // Console.WriteLine($"tcp and src host {ip} and src port {port}");
            
            //selectedDevice.Filter = filter;

            //starts capture
            selectedDevice.StartCapture();
           // scanPorts();
            //System.Threading.Thread.Sleep(timeout);
           // selectedDevice.StopCapture();
            //selectedDevice.Close();
            return selectedDevice;
        }

        /// <summary>
        /// Scans the specified TCP and UDP ports for given IP addresses using raw packet transmission.
        /// The method sends TCP SYN packets and UDP packets, then listens for responses to determine the port status.
        /// </summary>
        /// <param name="args">Scanner arguments containing target addresses, ports, interface name, and timeout.</param>
        /// <param name="device">The network capture device used for packet capturing.</param>
        public static void scanPorts(ScannerArgs args, ICaptureDevice device)
        {
            // args scanner calling
            var ipAddresses = ArgumentParser.ipParse(args);
            var tcpPorts = args.TcpPorts;
            var udpPorts = args.UdpPorts;
            var interfaceName = args.Interface;
            var timeout = args.Timeout;

            foreach (var ipAddress in ipAddresses)
            {
                foreach (var port in tcpPorts)
                {
                    //Console.WriteLine("\nTCP\n");
                    //Console.WriteLine($"{ipAddress.Key}");
                    string filter = $"tcp and src host {ipAddress.Key} and src port {port}";
                    using (var waitHandle = new ManualResetEventSlim(false))  // Event na blokovanie
                    {
                        try
                        {
                            device.Filter = filter;  //Sets filter
                           // Console.WriteLine($"Set filter: {filter}");

                            void PacketHandler(object s, PacketCapture e)
                            {
                                waitHandle.Set();  //Unlocks thread if pacekt arrived
                            }
                            device.OnPacketArrival += PacketHandler;
                            
                            //Sends syn packet
                            Scanner.sendPacket(port, ipAddress.Key, ipAddress.Value, interfaceName, true);
                            if (!waitHandle.Wait(timeout)) 
                            {
                                //if there was no answer, we will send another packet to be sure
                                Scanner.sendPacket(port, ipAddress.Key, ipAddress.Value, interfaceName, true);
                                if (!waitHandle.Wait(timeout)) 
                                {
                                    Console.WriteLine($"{ipAddress.Key} {port} tcp filtered");
                                }
                            }
                            device.OnPacketArrival -= PacketHandler;
                        }
                        catch (Exception e)
                        {
                            Console.Error.WriteLine($"Error setting filter or sending packet: {e.Message}");
                        }
                    }
                }
                foreach (var port in udpPorts)
                {
                    //udp icmp filter
                    string filter = $"(icmp[0] == 3 and icmp[1] == 3) or (icmp6[0] == 1 and icmp6[1] == 4)";
                    using (var waitHandle = new ManualResetEventSlim(false))
                    {
                        try
                        {
                            device.Filter = filter;
                           // Console.WriteLine($"Set filter: {filter} and src port {port}");

                            void PacketHandler(object s, PacketCapture e)
                            {
                                waitHandle.Set();  //Unlocks thread after packet is recived
                            }
                            device.OnPacketArrival += PacketHandler;
                            
                            // Sends UDP packet
                            //Console.WriteLine($"{port}");
                            Scanner.sendPacket(port, ipAddress.Key, ipAddress.Value, interfaceName, false);

                            //waits for ICMP response
                            if (!waitHandle.Wait(timeout)) 
                            {
                                //if ICMP was not recived
                                Console.WriteLine($"{ipAddress.Key} {port} udp open");
                            }
                            device.OnPacketArrival -= PacketHandler;
                        }
                        catch (Exception e)
                        {
                            Console.Error.WriteLine($"Error setting filter or sending packet: {e.Message}");
                        }
                    }

                }
                
            }
            device.StopCapture();
            device.Close();
        }

        /// <summary>
        /// Handles incoming packets, determines whether the scanned port is open, closed, or filtered.
        /// </summary>
        public static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            // gets packet
            var rawPacket = e.GetPacket();
            //transforms packet to byte array
            byte[] data = rawPacket.Data;
           // Console.WriteLine($"\n");
            //PrintPacket(data);
            //Console.WriteLine($"Prijmam packet: o dlzke {data.Length}\n");

            //checks minimal packet length
            if (data.Length < 34){ 
                Console.WriteLine("Invalid packet length");
                Environment.Exit(1);
            }
            
            int offset = 0;
            //adds ofset if ethernet 
            if (rawPacket.LinkLayerType.ToString().Equals("Ethernet"))
            {
                offset = 10;//20 pr eipv6
                Console.WriteLine($"\n ETHERNET \n");
            }

            // gets version = IPv6 or IPv4, and header length
            byte versionAndHeaderLength = data[4 + offset];
            byte version = (byte)((versionAndHeaderLength >> 4) & 0x0F);
            byte ipHeaderLength = (byte)((versionAndHeaderLength & 0x0F) * 4); 
           // Console.WriteLine($"IP Version: {version}");
            //Console.WriteLine($"ethtype: {etherType}");
            //return;

            //IPv4 section
            if (version == 4)
            {
                //gets protocol type out of packet data
                byte protocol = data[13 + offset];
               // Console.WriteLine($"Protocol prichadzajuceho je: {protocol}");
                //return;
               // Console.WriteLine("Received IPv4 Packet");
        
                if (protocol == 6) // TCP
                {
                    string sourceIP = new IPAddress(new ReadOnlySpan<byte>(data, 20 + offset, 4)).ToString();
                    ushort sourcePort = (ushort)((data[24 + offset] << 8) | data[25 + offset]);
                    //Console.WriteLine("TCP Packet");
                   // Console.WriteLine($"ip: {sourceIP}");
                    
                    // TCP hreader starts after IP header
                    int tcpOffset = 4 + ipHeaderLength; // 4 je offset prvých metadát
                    
                    // Gets TCP flags
                    byte tcpFlags = data[tcpOffset + 13 + offset];
                    
                    // Analyze TCP flags
                    bool isFIN = (tcpFlags & 0x01) != 0;
                    bool isSYN = (tcpFlags & 0x02) != 0;
                    bool isRST = (tcpFlags & 0x04) != 0;
                    bool isPSH = (tcpFlags & 0x08) != 0;
                    bool isACK = (tcpFlags & 0x10) != 0;
                    bool isURG = (tcpFlags & 0x20) != 0;
                    
                   //Console.WriteLine($"TCP Flags: FIN={isFIN}, SYN={isSYN}, RST={isRST}, PSH={isPSH}, ACK={isACK}, URG={isURG}");
                    
                    // Based on assignment
                    if (isRST)
                    {
                        Console.WriteLine($"{sourceIP} {sourcePort} tcp closed");
                    }
                    else if (isSYN && isACK)
                    {
                        Console.WriteLine($"{sourceIP} {sourcePort} tcp open");
                    }
                //UDP section
                }else if(protocol == 1){
                    //Console.WriteLine($"{data[25]}");
                    string sourceIP = new IPAddress(new ReadOnlySpan<byte>(data, 48 + offset, 4)).ToString();
                    ushort sourcePort = (ushort)((data[54 + offset] << 8) | data[55 + offset]);
                    //Console.WriteLine($"ip:{sourceIP} port: {sourcePort}");
                   // if(data[24 + offset] == 3 && data[25 + offset] == 3){  
                        Console.WriteLine($"{sourceIP} {sourcePort} udp closed");
                   // }else{
                        //Console.WriteLine($"{sourceIP} {sourcePort} udp open");
                   // }
                    
                    //Console.WriteLine("UDP Packet");
                }
                
            }
            //IPv6 part
            else if (version == 6)
            {
                byte protocol = data[10 + offset];
               //Console.WriteLine($"Protocol prichadzajuceho je: {protocol}");
                //return;
                //TCP part
                if(protocol == 6){
                    string sourceIP = new IPAddress(new ReadOnlySpan<byte>(data, 28 + offset, 16)).ToString();
                    ushort sourcePort = (ushort)((data[44 + offset] << 8) | data[45 + offset]);
                    //Console.WriteLine("Received IPv6 Packet");
                    //Console.WriteLine($"ip: {sourceIP}");
                    //Console.WriteLine($"port: {sourcePort}");

                    //TCP header starts after IPv6 header = offset 40
                    int tcpOffset = 40;

                    // Gets TCP flags
                    byte tcpFlags = data[tcpOffset + 17 + offset];

                    // TCP flags analysis
                    bool isFIN = (tcpFlags & 0x01) != 0;
                    bool isSYN = (tcpFlags & 0x02) != 0;
                    bool isRST = (tcpFlags & 0x04) != 0;
                    bool isPSH = (tcpFlags & 0x08) != 0;
                    bool isACK = (tcpFlags & 0x10) != 0;
                    bool isURG = (tcpFlags & 0x20) != 0;
                   // Console.WriteLine($"TCP Flags: FIN={isFIN}, SYN={isSYN}, RST={isRST}, PSH={isPSH}, ACK={isACK}, URG={isURG}");

                    // Based on assignment
                    if (isRST)
                    {
                        Console.WriteLine($"{sourceIP} {sourcePort} tcp closed");
                    }
                    else if (isSYN && isACK)
                    {
                        Console.WriteLine($"{sourceIP} {sourcePort} tcp open");
                    }
                //UDP part
                }else if(protocol == 58){
                    string sourceIP = new IPAddress(new ReadOnlySpan<byte>(data, 76 + offset, 16)).ToString();
                    ushort sourcePort = (ushort)((data[94 + offset] << 8) | data[95 + offset]);
                   // if(data[44 + offset] == 1 && data[45 + offset] == 4){
                        Console.WriteLine($"{sourceIP} {sourcePort} udp closed");
                   // }
                    //Console.WriteLine("UDP Packet");
                }
            }
               // PrintPacket(data);

        }
        /// <summary>
        /// Helper function to print packet
        /// </summary>
        public static void PrintPacket(byte[] packet)
        {
            if (packet == null || packet.Length == 0)
            {
                Console.WriteLine("\nPacket is empty or null");
                return;
            }

            // Každý byte v pakete vypíšeme ako hexadecimálnu hodnotu
            for (int i = 0; i < packet.Length; i++)
            {
                // Vypíše každú hodnotu v hexadecimálnom formáte
                Console.Write($"{packet[i]:X2} ");

                // Prehľadne pridáme nový riadok každých 16 byte-ov (pre lepšiu čitateľnosť)
                if ((i + 1) % 16 == 0)
                {
                    Console.WriteLine(); // nový riadok po každom 16. byte
                }
            }

            Console.WriteLine(); // na konci pridáme prázdny riadok
        }

        //----------------------------------------------------------------IPV4

        /// <summary>
        /// Creates a TCP SYN packet for IPv4 communication.
        /// </summary>
        /// <param name="ip">The destination IP address.</param>
        /// <param name="port">The destination port number.</param>
        /// <param name="interfaceName">The name of the network interface to use for sending the packet.</param>
        /// <returns>A byte array representing the raw TCP SYN packet.</returns>
        /// <remarks>
        /// This method constructs a TCP SYN packet manually, including the IP header and TCP header.
        /// The following key elements are set:
        /// - Source and destination IP addresses.
        /// - Randomized source port.
        /// - Destination port as specified.
        /// - A randomly generated sequence number.
        /// - Flags set to indicate a SYN request.
        /// - Window size and TCP checksum calculation.
        /// 
        /// The generated packet is used for scanning or establishing an initial TCP connection request.
        /// </remarks>
        public static byte[] CreateTcpSynPacket4(IPAddress ip, int  port, string interfaceName){
            byte [] packet = new byte[20];

            IPAddress myIPv4 =  GetLocalIPAddress(interfaceName, true);
            byte[] srcIpBytes = myIPv4.GetAddressBytes();
            byte[] desIpBytes = ip.GetAddressBytes();
            Array.Copy(srcIpBytes, 0, packet, 12, 4);
            Array.Copy(desIpBytes, 0, packet, 16, 4);

            // TCP Header (20 B)
            Random random = new Random();
            ushort sourcePort = (ushort)random.Next(1024, 65535);
            packet[0] = (byte)(sourcePort >> 8); 
            packet[1] = (byte)(sourcePort & 0xFF); 

            packet[2] = (byte)(port >> 8);  // Destination port 
            packet[3] = (byte)(port & 0xFF);
            Random randomSeq = new Random();
            int seqNo = random.Next(0, int.MaxValue);
            // Sequence Number (4 B) - random
            
            // sets seq number
            packet[4] = (byte)(seqNo >> 24); 
            packet[5] = (byte)(seqNo >> 16);  
            packet[6] = (byte)(seqNo >> 8);   
            packet[7] = (byte)(seqNo & 0xFF); 

            // Acknowledgment Number (4 B) - in SYN paket is 0
            packet[8] = 0x00; packet[9] = 0x00; packet[10] = 0x00; packet[11] = 0x00;

            packet[12] = 0x50; // Data Offset (5 = 20 B), Reserved, NS flag
            packet[13] = 0x02; // Flags = SYN (0b00000010)
            packet[14] = 0xFF; packet[15] = 0xFF;

            packet[17] = 0x00;
            packet[16] = 0x00;
            packet[18] = 0x00;
            packet[19] = 0x00;
            ushort checksumTcp = CalculateTcpChecksum(myIPv4, ip, packet);
            packet[17] = (byte)(checksumTcp & 0xFF);
            packet[16] = (byte)(checksumTcp >> 8);

            return packet;
        }

        /// <summary>
        /// Creates a TCP pseudo-header for checksum calculation.
        /// </summary>
        /// <param name="srcIP">The source IPv4 address.</param>
        /// <param name="destIP">The destination IPv4 address.</param>
        /// <param name="tcpHeader">The TCP header and data.</param>
        /// <returns>A byte array representing the pseudo-header.</returns>
        /// <remarks>
        /// The pseudo-header is used in TCP checksum calculation and includes the following fields:
        /// - Source IP address (4 bytes)
        /// - Destination IP address (4 bytes)
        /// - Reserved byte (1 byte, set to 0)
        /// - Protocol (1 byte, set to 0x06 for TCP)
        /// - TCP segment length (2 bytes)
        /// 
        /// The pseudo-header is not transmitted over the network but is required for checksum verification.
        /// </remarks>
        public static byte[] CreateTcpPseudoHeader(IPAddress srcIP, IPAddress destIP, byte[] tcpHeader)
        {
            // Pseudo header: 
            byte[] pseudoHeader = new byte[12];

            // Source IP
            byte[] srcIpBytes = srcIP.GetAddressBytes();
            Array.Copy(srcIpBytes, 0, pseudoHeader, 0, 4);

            // Destination IP
            byte[] destIpBytes = destIP.GetAddressBytes();
            Array.Copy(destIpBytes, 0, pseudoHeader, 4, 4);

            pseudoHeader[8] = 0x00;
            // Protokol - TCP (0x06)
            pseudoHeader[9] = 0x06;

            ushort tcpLength = (ushort)(tcpHeader.Length);
            pseudoHeader[10] = (byte)(tcpLength >> 8);
            pseudoHeader[11] = (byte)(tcpLength & 0xFF);

            return pseudoHeader;
        }

        /// <summary>
        /// Calculates the TCP checksum for a given TCP segment.
        /// </summary>
        /// <param name="srcIP">The source IPv4 address.</param>
        /// <param name="destIP">The destination IPv4 address.</param>
        /// <param name="tcpHeader">The TCP header and payload.</param>
        /// <returns>The computed TCP checksum as a 16-bit unsigned integer.</returns>
        /// <remarks>
        /// This method calculates the TCP checksum by:
        /// - Creating a pseudo-header using the source and destination IP addresses.
        /// - Concatenating the pseudo-header with the TCP segment.
        /// - Computing the checksum over the combined data.
        ///
        /// The checksum is required for TCP segment integrity verification.
        /// </remarks>
        public static ushort CalculateTcpChecksum(IPAddress srcIP, IPAddress destIP, byte[] tcpHeader)
        {
            // Vytvoríme pseudo-hlavičku
            byte[] pseudoHeader = CreateTcpPseudoHeader(srcIP, destIP, tcpHeader);

            // Kombinujeme pseudo-hlavičku s TCP hlavičkou
            byte[] fullPacket = new byte[pseudoHeader.Length + tcpHeader.Length];
            Array.Copy(pseudoHeader, 0, fullPacket, 0, pseudoHeader.Length);
            Array.Copy(tcpHeader, 0, fullPacket, pseudoHeader.Length, tcpHeader.Length);

            // Vypočítať checksumu pre celý paket
            return CalculateChecksum(fullPacket);
        }
        
        /// <summary>
        /// Calculates the Internet checksum for the given header data.
        /// </summary>
        /// <param name="header">A byte array containing the header data.</param>
        /// <returns>The computed checksum as a 16-bit unsigned integer.</returns>
        /// <remarks>
        /// The checksum is calculated as follows:
        /// - The data is processed in 16-bit words, summing them together.
        /// - If there is an overflow (carry bit), it is added back to the sum.
        /// - The final result is bitwise inverted to produce the checksum.
        /// 
        /// This method is used for checksum validation in networking protocols such as IP, TCP, and UDP.
        /// </remarks>
        private static ushort CalculateChecksum(byte[] header) {
            uint sum = 0;
            
            for (int i = 0; i < header.Length; i += 2) {
                ushort word = (ushort)((header[i] << 8) | header[i + 1]);
                sum += word;
            }
            
            while ((sum >> 16) > 0) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            return (ushort)~sum;
        }

        /// <summary>
        /// Retrieves the local IP address of the specified network interface.
        /// </summary>
        /// <param name="interfaceName">The name of the network interface.</param>
        /// <param name="isIpv4">A boolean indicating whether to return an IPv4 (true) or IPv6 (false) address.</param>
        /// <returns>The local IP address of the specified network interface, or null if not found.</returns>
        /// <remarks>
        /// This method performs the following steps:
        /// - Retrieves all available network interfaces.
        /// - Searches for the specified interface by name.
        /// - Checks if the interface is active.
        /// - Iterates through the assigned IP addresses to return either an IPv4 or IPv6 address based on the parameter.
        /// 
        /// If the interface is not found or is inactive, an error message is printed, and the program exits.
        /// IPv6 link-local and site-local addresses are excluded when searching for an IPv6 address.
        /// </remarks>
        public static IPAddress GetLocalIPAddress(string interfaceName, bool isIpv4 )
        {
            //gets all net interfaces
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            //searches for interface based on interfaceName
            NetworkInterface selectedInterface = interfaces.FirstOrDefault(netInterface => netInterface.Name == interfaceName);

            if (selectedInterface != null)
            {
                //checks if interface is UP
                if (selectedInterface.OperationalStatus == OperationalStatus.Up)
                {
                    //gets IP characteristics of interface
                    IPInterfaceProperties ipProperties = selectedInterface.GetIPProperties();
                    
                    foreach (var unicastAddress in ipProperties.UnicastAddresses)
                    {
                        //filter for Ipv4 a Ipv6
                        if (unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && isIpv4) // IPv4
                        {
                            return unicastAddress.Address;
                        }
                        else if (unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&  !isIpv4 && !unicastAddress.Address.IsIPv6LinkLocal && !unicastAddress.Address.IsIPv6SiteLocal) // IPv6
                        {
                            return unicastAddress.Address;
                        }
                    }
                }
                else
                {
                    Console.Error.WriteLine("Interface is down.");
                    Environment.Exit(1);
                }
            }
            else
            {
                Console.Error.WriteLine($"Network interface {interfaceName} not found.");
                Environment.Exit(1);
            }
            return null;
        }

// ----------------------------------------------------------------IPV6

        /// <summary>
        /// Creates a raw TCP SYN packet for IPv6 communication.
        /// </summary>
        /// <param name="ip">The destination IPv6 address.</param>
        /// <param name="port">The destination port number.</param>
        /// <param name="interfaceName">The name of the network interface used to obtain the source IPv6 address.</param>
        /// <returns>A byte array containing the constructed TCP SYN packet.</returns>
        /// <remarks>
        /// This method constructs a TCP SYN packet for IPv6 communication by setting the following key fields:
        /// - Source and destination IP addresses.
        /// - A randomly generated source port.
        /// - The specified destination port.
        /// - A randomly generated sequence number.
        /// - TCP flags configured for a SYN request.
        /// - A default window size.
        /// - A computed TCP checksum for integrity verification.
        /// 
        /// The generated packet is used for network scanning or initiating a TCP handshake over IPv6.
        /// </remarks>
        public static byte[] CreateTcpSynPacket6(IPAddress ip, int  port, string interfaceName){
            byte [] packet = new byte[40];
            //  // Source IP address
             IPAddress myIPv6 = GetLocalIPAddress(interfaceName, false);

            // TCP header (20 B)
            Random random = new Random();
            ushort sourcePort = (ushort)random.Next(1024, 65535);
            packet[0] = (byte)(sourcePort >> 8); 
            packet[1] = (byte)(sourcePort & 0xFF);

            packet[2] = (byte)(port >> 8);  //Source port
            packet[3] = (byte)(port & 0xFF); 

            int seqNo = random.Next(0, int.MaxValue);
            packet[4] = (byte)(seqNo >> 24);  
            packet[5] = (byte)(seqNo >> 16);  
            packet[6] = (byte)(seqNo >> 8);   
            packet[7] = (byte)(seqNo & 0xFF);

            // Acknowledgment Number (4 B) = 0 pre SYN
            packet[8] = 0x00; packet[9] = 0x00; packet[10] = 0x00; packet[11] = 0x00;
            // Flags = SYN (0x02)
            packet[12] = 0x50; // Data Offset (5 = 20 B), Reserved, NS flag
            packet[13] = 0x02; // Flags = SYN
            // Window size
            packet[14] = 0x72; packet[15] = 0x10;

            ushort checksumTcp = CalculateTcpChecksumIPv6(myIPv6, ip, packet);  // checksum calculation
            packet[16] = (byte)(checksumTcp >> 8);  // Higher B checksumu
            packet[17] = (byte)(checksumTcp & 0xFF);  // Lower B checksumu

            packet[18] = 0x00;  // Urgent pointer
            packet[19] = 0x00;
            return packet;
        }
        
        /// <summary>
        /// Creates a TCP pseudo-header for IPv6 communication for checksum calculation.
        /// </summary>
        /// <param name="srcIP">The source IPv6 address.</param>
        /// <param name="destIP">The destination IPv6 address.</param>
        /// <param name="tcpHeader">The TCP header and data.</param>
        /// <returns>A byte array representing the TCP pseudo-header for IPv6.</returns>
        /// <remarks>
        /// This method creates a pseudo-header used in the TCP checksum calculation for IPv6. The pseudo-header includes:
        /// - Source IPv6 address (16 bytes)
        /// - Destination IPv6 address (16 bytes)
        /// - TCP payload length (2 bytes)
        /// - Protocol type (1 byte, set to 0x06 for TCP)
        /// 
        /// The pseudo-header is not transmitted over the network but is essential for calculating the TCP checksum.
        /// </remarks>
        public static byte[] CreateTcpPseudoHeaderIPv6(IPAddress srcIP, IPAddress destIP, byte[] tcpHeader)
        {
            byte[] pseudoHeader = new byte[40];

            // Source IPv6
            byte[] srcIpBytes = srcIP.GetAddressBytes();
            Array.Copy(srcIpBytes, 0, pseudoHeader, 0, 16);

            // Destination IPv6
            byte[] destIpBytes = destIP.GetAddressBytes();
            Array.Copy(destIpBytes, 0, pseudoHeader, 16, 16);

            // Payload length (16-bit)
            ushort tcpLength = (ushort)(tcpHeader.Length);
            pseudoHeader[32] = (byte)(tcpLength >> 8);
            pseudoHeader[33] = (byte)(tcpLength & 0xFF);

            // Next header (protokol TCP = 6)
            pseudoHeader[34] = 0x00;
            pseudoHeader[35] = 0x06;

            return pseudoHeader;
        }
        
        /// <summary>
        /// Calculates the TCP checksum for a given TCP segment over IPv6.
        /// </summary>
        /// <param name="srcIP">The source IPv6 address.</param>
        /// <param name="destIP">The destination IPv6 address.</param>
        /// <param name="tcpHeader">The TCP header and data.</param>
        /// <returns>The computed TCP checksum as a 16-bit unsigned integer.</returns>
        /// <remarks>
        /// This method calculates the TCP checksum over IPv6 by:
        /// - Creating a pseudo-header using the source and destination IPv6 addresses.
        /// - Concatenating the pseudo-header with the TCP segment.
        /// - Computing the checksum over the combined data.
        ///
        /// The checksum is used to verify the integrity of the TCP segment and ensure reliable data transmission.
        /// </remarks>
        public static ushort CalculateTcpChecksumIPv6(IPAddress srcIP, IPAddress destIP, byte[] tcpHeader)
        {
            // creates pseudoheader
            byte[] pseudoHeader = CreateTcpPseudoHeaderIPv6(srcIP, destIP, tcpHeader);

            //combines pseudoheader and TCP header
            byte[] fullPacket = new byte[pseudoHeader.Length + tcpHeader.Length];
            Array.Copy(pseudoHeader, 0, fullPacket, 0, pseudoHeader.Length);
            Array.Copy(tcpHeader, 0, fullPacket, pseudoHeader.Length, tcpHeader.Length);

            // Calculates check sum for whole packet
            return CalculateChecksum(fullPacket);
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            try
            {   
                ScannerArgs parsedArgs = ArgumentParser.Parse(args);      
                ICaptureDevice device = Scanner.startScan(parsedArgs.Interface);
                Scanner.scanPorts( parsedArgs,device);
                
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
}