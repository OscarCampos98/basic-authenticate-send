# basic-authenticate-send

# Introduction: 
This project addresses the secure exchange of data between a Client and a Server without 
requiring a pre-shared private key, focusing on a protocol that allows both parties to generate a 
private key on-the-fly. It tackles the challenge of secure authentication and key exchange in a 
scenario where the direct transmission of sensitive data or keys through an insecure channel is 
not feasible, allowing for password verification without storing password-equivalent data on the server side. 

The program supports three main actions:
  Client: Handles registration, key negotiation, and file transfer.
  Server: Launches the server to receive connections from clients.
  Quit: Allows the client to send a termination request to the server.
 
# File Descriptions:

basic_auth_and_send.py: This Python script implements the protocol for secure key exchange 
  and communication between a client and a server. It includes the definitions of necessary
  cryptographic operations, client-server communication protocols, and high-level functions for
  registration, key exchange, and file transfer.

# Main Functions:
  client_handshake:
    Handles the first message between the client and the server, ensuring consistent server parameters 
    and initiating the connection.

  client_register:
    Registers the client with the server by sending the necessary credentials (username, password) 
    and calculated values like the salt and verifier.

  server_register:
    Handles the server's side of client registration, updating the client database and ensuring that the
    received values (salt, verifier, etc.) are valid.
    
  client_key:
    Responsible for key negotiation on the client-side, generating the necessary values and sending them
    to the server to establish a shared secret key.
  
  server_key:
    Complements client_key, handling the server-side key negotiation and generating the server's shared key.

  client_file and server_file:
    Handle file transfer between the client and the server, using the established shared key for encryption and
    decryption.
 
# Known Limitations/and Bugs 
(update 1) 
The old version did not fully implement the following high-level functions: 
    - client_handshake() 
        - Fails: 31.1) Test if client_handshake() can receive the initial message from the 
        Server and do initialization. (0/0.75) 
        - Possible bug: The failure may stem from improper handling of partial message 
        reception and or incorrect message length calculation.
            - this was fixed on 2024-08-25   
    - client_register()
        - this was fixed on 2024-08-25   
    - server_register() 
        - this was fixed on 2024-08-25  
    - client_key() 
        - this was fixed on 2024-08-25  
    - server_key() 
        - this was fixed on 2024-08-25  
    - client_file() 
        - this was fixed on 2024-08-25  
    - server_file() 
        - this was fixed on 2024-08-25  
    
(current!)
Client-Server Key Negotiation Issue:
  -When both the solution and your code are executed to negotiate the shared key between the
        client and server, a flaw is observed during the key calculation phase.

  -Server Logs: The server successfully receives the 	client's request, registers the user, 
        and begins the shared key negotiation, generating the values 𝐴,𝐵,𝑢,and 𝐾_server.
         However, the server terminates the connection due to a secret negotiation failure.

  -Client Logs: The client receives the server's handshake and registration confirmation,
         but when attempting to calculate the shared key, throw errors. Specifically,
          the following exceptions are raised:
          -TypeError: unsupported operand type(s) for *: 'NoneType' and 'int' during the 
            calculation of 𝐾_𝑐𝑙𝑖𝑒𝑛𝑡

Testing:

Testing was conducted to evaluate the functionality of the client and server processes in handling secure communication.
The tests were performed using two terminals: one for the server and the other for the client.

  Launching the Server: The server was initiated using the following command:

    -python basic_auth_and_send.py --addr 127.0.4.18:3180 --server -v
  
  The server generates necessary security parameters (such as N and g) and waits for incoming client connections.

  Client Connection: The client was initiated with the following command:
  
    -python basic_auth_and_send.py --addr 127.0.4.18:3180 --client -v
  
  The client connects to the server, performs the handshake, registers itself, and then attempts to negotiate
  a shared key.

  Quit Command: The quit flag was tested by sending a termination request to the server, successfully terminating the 
  server as expected:
  
    -python basic_auth_and_send.py --addr 127.0.4.18:3180 --quit -v       


Extra information:

Prime Generation and Primitive Root Selection 
    Prime Generation:  
    The safe_prime function generates a cryptographically secure safe prime N for cryptographic 
    applications, this process begins with the generation of a random number of the specified bit 
    length using a fast, cryptographically secure pseudo-random number generator (FastCSPRNG). 
    The generated number is then checked for primality using the sympy.isprime() function. A safe 
    prime is a prime p where (p-1)/2 is also prime.   
    following these steps: 
        - Random Number Generation: Utilizes FastCSPRNG to create a random number of the 
            specified bit length, ensuring cryptographic security. 
        - Setting the Highest Bit: The operation candidate |= (1 << (bits - 1)) ensures the highest bit 
            is set. This is crucial for the number to reach the desired bit length, effectively using a 
            bitwise OR operation to set the most significant bit to 1. 
        - Ensuring Oddness: The candidate |= 1 step ensures the number is odd by setting the least 
            significant bit to 1, again using bitwise OR. This is important because all prime numbers 
            greater than 2 are odd. 
        - Primality Checks: Verifies if the candidate is a safe prime by checking both the candidate 
            and (candidate - 1) / 2 for primality, ensuring the number and its half-minus-one are 
            prime, a requirement for safe primes in cryptographic applications. 
            Primitive Root Selection: The prim_root function finds a primitive root modulo a prime number, 
            essential for Diffie-Hellman key exchange. This process involves selecting a number and 
            verifying it satisfies the criteria for being a primitive root N. A primitive root is an integer whose 
            powers, when taken modulo N, generate all possible residues modulo N.  
            It follows this steps: 
        - Input Conversion: The function takes N as input, which can be either an integer or a bytes 
            object representing the large safe prime. 
        - Calculation of q: It calculates q as half of N−1, given that N is a safe prime. This is 
            because a primitive root g modulo N has to satisfy the condition g^q ≠ 1 (mod N). 
        - Primitive Root Verification: The function defines an inner function ‘is_primitive_root(g, 
            N, q)’ to check if a number g is a primitive root modulo N. It checks whether g^q≠ 1 
            (mod N) indicating that g is not congruent to 1. 
        - Iterative Search for Primitive Root: The function iterates through potential candidates for 
            g starting from 2 up to N – 1. For each candidate g, it checks if it satisfies the primitive 
            root condition using the is_primitive_root function. 
        - Return: Once a primitive root is found, the function returns it.
