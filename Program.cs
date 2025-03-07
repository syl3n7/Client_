using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;

class TCPClient
{
    static bool isRunning = true;
    static readonly string savedUsersFile = "savedUsers.txt";
    static readonly string savedServersFile = "savedServers.txt";
    static List<string> savedUsers = new List<string>();
    static List<string> savedServers = new List<string>(); // Format: "ip:port:secure" - secure is "true" or "false"

    static void Main(string[] args)
    {
        LoadSavedUsers();
        LoadSavedServers();
        
        string ipAddress = "127.0.0.1"; // Default value
        int port = 12345; // Default value
        bool useSecureConnection = false; // Default to non-secure

        try
        {
            // Check if we have saved servers and offer them as options
            if (savedServers.Count > 0)
            {
                Console.WriteLine("Saved servers:");
                for (int i = 0; i < savedServers.Count; i++)
                {
                    string[] parts = savedServers[i].Split(':');
                    string secureLabel = parts.Length > 2 && parts[2] == "true" ? " (Secure)" : "";
                    Console.WriteLine($"{i + 1}. {parts[0]}:{parts[1]}{secureLabel}");
                }
                Console.WriteLine($"{savedServers.Count + 1}. Connect to a new server");
                
                Console.Write("\nSelect an option: ");
                if (int.TryParse(Console.ReadLine(), out int serverChoice) && 
                    serverChoice >= 1 && serverChoice <= savedServers.Count + 1)
                {
                    if (serverChoice <= savedServers.Count)
                    {
                        string[] parts = savedServers[serverChoice - 1].Split(':');
                        ipAddress = parts[0];
                        port = int.Parse(parts[1]);
                        useSecureConnection = parts.Length > 2 && parts[2] == "true";
                    }
                    else
                    {
                        // New server connection
                        PromptForServerDetails(ref ipAddress, ref port, ref useSecureConnection);
                    }
                }
                else
                {
                    // Invalid input, prompt for new details
                    PromptForServerDetails(ref ipAddress, ref port, ref useSecureConnection);
                }
            }
            else
            {
                // No saved servers, prompt for details
                PromptForServerDetails(ref ipAddress, ref port, ref useSecureConnection);
            }

            Console.WriteLine($"Connecting to {ipAddress}:{port} {(useSecureConnection ? "(Secure)" : "(Non-secure)")}...");
            
            TcpClient client = new TcpClient();
            
            // Set connection timeout (5 seconds)
            IAsyncResult ar = client.BeginConnect(ipAddress, port, null, null);
            bool connected = ar.AsyncWaitHandle.WaitOne(5000); // 5 second timeout
            
            if (!connected)
            {
                throw new TimeoutException("Connection attempt timed out. Server may be offline.");
            }
            
            client.EndConnect(ar);
            
            // Create appropriate stream based on connection type
            Stream baseStream = client.GetStream();
            Stream communicationStream;
            
            if (useSecureConnection)
            {
                // Create secure stream
                SslStream sslStream = new SslStream(baseStream, false, 
                    new RemoteCertificateValidationCallback(ValidateServerCertificate));
                
                try
                {
                    // Authenticate as client
                    sslStream.AuthenticateAsClient(ipAddress);
                    Console.WriteLine("Secure connection established successfully.");
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine($"SSL Authentication failed: {e.Message}");
                    client.Close();
                    return;
                }
                
                communicationStream = sslStream;
            }
            else
            {
                // Use standard network stream
                communicationStream = baseStream;
            }
            
            // Buffer for incoming messages
            byte[] buffer = new byte[1024];
            int bytesRead;
            
            // After successful connection, ask to save the server if it's not already saved
            string serverEntry = $"{ipAddress}:{port}:{useSecureConnection}";
            // Check if this exact server configuration is already saved
            bool serverAlreadySaved = false;
            foreach (string server in savedServers)
            {
                if (server.Split(':')[0] == ipAddress && 
                    server.Split(':')[1] == port.ToString() &&
                    (server.Split(':').Length <= 2 || server.Split(':')[2] == useSecureConnection.ToString().ToLower()))
                {
                    serverAlreadySaved = true;
                    break;
                }
            }
            
            if (!serverAlreadySaved)
            {
                Console.Write("Remember this server for future connections? (y/n): ");
                string rememberChoice = Console.ReadLine();
                if (rememberChoice.ToLower() == "y" || rememberChoice.ToLower() == "yes")
                {
                    savedServers.Add(serverEntry);
                    SaveServers();
                    Console.WriteLine("Server saved!");
                }
            }
            
            // Read welcome message
            try
            {
                bytesRead = communicationStream.Read(buffer, 0, buffer.Length);
                Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, bytesRead));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading welcome message: {ex.Message}");
                throw;
            }
            
            // Authentication loop
            bool isAuthenticated = false;
            while (!isAuthenticated && client.Connected)
            {
                Console.WriteLine("\nOptions:");
                Console.WriteLine("1. Login");
                Console.WriteLine("2. Register");
                Console.Write("> ");
                
                string choice = Console.ReadLine();
                string username = "";
                string password = "";
                bool isLogin = choice == "1";
                
                if (choice == "1" || choice == "2")
                {
                    // Handle username input
                    if (isLogin && savedUsers.Count > 0)
                    {
                        Console.WriteLine("\nSaved users:");
                        for (int i = 0; i < savedUsers.Count; i++)
                        {
                            Console.WriteLine($"{i + 1}. {savedUsers[i]}");
                        }
                        Console.WriteLine($"{savedUsers.Count + 1}. Use a new username");
                        
                        Console.Write("\nSelect an option: ");
                        if (int.TryParse(Console.ReadLine(), out int userChoice) && 
                            userChoice >= 1 && userChoice <= savedUsers.Count + 1)
                        {
                            if (userChoice <= savedUsers.Count)
                            {
                                username = savedUsers[userChoice - 1];
                            }
                            else
                            {
                                Console.Write("Enter username: ");
                                username = Console.ReadLine();
                            }
                        }
                        else
                        {
                            Console.Write("Enter username: ");
                            username = Console.ReadLine();
                        }
                    }
                    else
                    {
                        Console.Write("Enter username: ");
                        username = Console.ReadLine();
                    }
                    
                    // Handle password input with masking
                    Console.Write("Enter password: ");
                    password = ReadPasswordWithMask();
                    
                    // Format command for server
                    string command = isLogin ? "/login " : "/register ";
                    command += $"{username}:{password}";
                    
                    // Send authentication request
                    byte[] data = Encoding.UTF8.GetBytes(command);
                    communicationStream.Write(data, 0, data.Length);
                    
                    // Get server response
                    try
                    {
                        bytesRead = communicationStream.Read(buffer, 0, buffer.Length);
                        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        Console.WriteLine(response);
                        
                        // Check if authentication was successful
                        if (response.Contains("successful"))
                        {
                            isAuthenticated = true;
                            Console.WriteLine("Authentication successful!");
                            
                            // If login is successful and the user isn't already saved, ask to remember
                            if (!savedUsers.Contains(username))
                            {
                                Console.Write("Remember this username for future logins? (y/n): ");
                                string rememberChoice = Console.ReadLine();
                                if (rememberChoice.ToLower() == "y" || rememberChoice.ToLower() == "yes")
                                {
                                    savedUsers.Add(username);
                                    SaveUsers();
                                    Console.WriteLine("Username saved!");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error during authentication: {ex.Message}");
                        throw;
                    }
                }
                else
                {
                    Console.WriteLine("Invalid option. Please choose 1 or 2.");
                }
            }
            
            // Create a thread to handle incoming messages
            Thread receiveThread = new Thread(() => ReceiveMessages(client, communicationStream));
            receiveThread.IsBackground = true;
            receiveThread.Start();
            
            // Show available commands
            DisplayLocalHelp();
            
            // Send messages
            Console.WriteLine("\nYou can now chat. Type '/help' for available commands.");
            while (client.Connected && isRunning)
            {
                string message = Console.ReadLine();
                
                // Handle local commands (those we don't want to send to server)
                if (string.IsNullOrEmpty(message))
                {
                    continue;
                }
                else if (message.Equals("/quit", StringComparison.OrdinalIgnoreCase) || 
                         message.Equals("/logout", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] data = Encoding.UTF8.GetBytes(message);
                    communicationStream.Write(data, 0, data.Length);
                    isRunning = false;
                    break;
                }
                else if (message.Equals("/clear", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Clear();
                    continue;
                }
                else if (message.Equals("/localhelp", StringComparison.OrdinalIgnoreCase))
                {
                    DisplayLocalHelp();
                    continue;
                }
                
                // Send message to server
                try
                {
                    byte[] messageData = Encoding.UTF8.GetBytes(message);
                    communicationStream.Write(messageData, 0, messageData.Length);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending message: {ex.Message}");
                    isRunning = false;
                    break;
                }
            }
        }
        catch (SocketException se)
        {
            Console.WriteLine($"Socket error: {se.Message}");
            Console.WriteLine("The server may be offline or unreachable. Please check your connection details and try again.");
        }
        catch (TimeoutException te)
        {
            Console.WriteLine($"Connection timeout: {te.Message}");
            Console.WriteLine("The server did not respond in a timely manner. It may be offline or congested.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            isRunning = false;
            Console.WriteLine("Disconnected from server.");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
    
    // Certificate validation callback
    private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        // For development: accept all certificates
        // In production, you should implement proper certificate validation
        if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
        {
            return true;
        }
        
        Console.WriteLine($"Certificate error: {sslPolicyErrors}");
        
        // Ask the user if they want to trust the certificate anyway
        Console.Write("The server's security certificate is not trusted. Connect anyway? (y/n): ");
        string response = Console.ReadLine().ToLower();
        return response == "y" || response == "yes";
    }
    
    // Prompt user for server details
    static void PromptForServerDetails(ref string ipAddress, ref int port, ref bool useSecureConnection)
    {
        // Prompt user for server IP address
        Console.WriteLine("Enter server IP address (press Enter for default 127.0.0.1):");
        string input = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(input))
            ipAddress = input;

        // Prompt user for server port
        Console.WriteLine("Enter server port (press Enter for default 12345):");
        input = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(input) && int.TryParse(input, out int customPort))
            port = customPort;
            
        // Prompt for secure connection
        Console.WriteLine("Use secure connection (SSL/TLS)? (y/n):");
        input = Console.ReadLine();
        useSecureConnection = input.ToLower() == "y" || input.ToLower() == "yes";
    }
    
    // Load saved servers from file
    static void LoadSavedServers()
    {
        try
        {
            if (File.Exists(savedServersFile))
            {
                savedServers = new List<string>(File.ReadAllLines(savedServersFile));
                
                // Convert old format to new format if needed
                for (int i = 0; i < savedServers.Count; i++)
                {
                    string[] parts = savedServers[i].Split(':');
                    if (parts.Length == 2)
                    {
                        // Old format without secure flag - assume non-secure
                        savedServers[i] = $"{parts[0]}:{parts[1]}:false";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading saved servers: {ex.Message}");
        }
    }
    
    // Save servers to file
    static void SaveServers()
    {
        try
        {
            File.WriteAllLines(savedServersFile, savedServers);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving servers: {ex.Message}");
        }
    }
    
    // Read password with masking characters
    static string ReadPasswordWithMask()
    {
        StringBuilder password = new StringBuilder();
        ConsoleKeyInfo key;
        
        do
        {
            key = Console.ReadKey(true);
            
            // Ignore any control or non-character keys except backspace and enter
            if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b"); // Erase the last * character
            }
        } while (key.Key != ConsoleKey.Enter);
        
        Console.WriteLine(); // Move to a new line
        return password.ToString();
    }
    
    // Load saved usernames from file
    static void LoadSavedUsers()
    {
        try
        {
            if (File.Exists(savedUsersFile))
            {
                savedUsers = new List<string>(File.ReadAllLines(savedUsersFile));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading saved users: {ex.Message}");
        }
    }
    
    // Save usernames to file
    static void SaveUsers()
    {
        try
        {
            File.WriteAllLines(savedUsersFile, savedUsers);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving users: {ex.Message}");
        }
    }
    
    static void ReceiveMessages(TcpClient client, Stream communicationStream)
    {
        byte[] buffer = new byte[1024];
        int bytesRead;
        
        try
        {
            while (client.Connected && isRunning)
            {
                bytesRead = communicationStream.Read(buffer, 0, buffer.Length);
                
                if (bytesRead == 0)
                {
                    Console.WriteLine("\nServer disconnected.");
                    isRunning = false;
                    break;
                }
                
                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                
                // Check if this is a kick or ban message
                if (message.Contains("You have been kicked") || 
                    message.Contains("Your account is banned"))
                {
                    Console.WriteLine($"\n{message}");
                    isRunning = false;
                    Thread.Sleep(3000); // Give user time to read the message
                    break;
                }
                
                // Format the output
                Console.WriteLine($"\n{message}");
                Console.Write("> "); // Reprint the prompt
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nReceive error: {ex.Message}");
            isRunning = false;
        }
    }
    
    static void DisplayLocalHelp()
    {
        Console.WriteLine("\n=== Client Commands ===");
        Console.WriteLine("/help - Show server commands");
        Console.WriteLine("/localhelp - Show client commands");
        Console.WriteLine("/clear - Clear console");
        Console.WriteLine("/quit or /logout - Disconnect from server");
        Console.WriteLine("\n=== Server Commands ===");
        Console.WriteLine("Use /help to see server commands");
        Console.WriteLine("/create-room [name] - Create a new room");
        Console.WriteLine("/join-room [name] - Join an existing room");
        Console.WriteLine("/list-rooms - List all available rooms");
        Console.WriteLine("/dm [username] [message] - Send private message");
        Console.WriteLine("/users - List users in your room");
    }
}