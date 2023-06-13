# wolfssl_android_tls_example_demo
This project explains the Handshake process between the Client and the Server manually using SSLEngine and WolfSSL as a Security Provider.

<h2>An Overiew of the SSL or TLS Handshake</h2>
The SSL or TLS handshake enables the SSL or TLS client and server to establish the secret keys with which they communicate.

This section provides a summary of the steps that enable the SSL or TLS client and server to communicate with each other.

- Agree on the version of the protocol to use
- Select cryptographic algorithms
- Authenticate each other by exchanging and validating digital certiticates.
- Use asymmetric encryption techniques to generate a shared secret key. which avoids the key distribution problem. SSL or TLS then uses the shared key for the symmetric encryption of messages, which is faster than asymmetric encryption.

In overview. the steps involved in the SSL handshake are as follows:
1. The SSL or TLS client sends a "client hello" message that lists cryptographic information such as the SSL or TLS version and, in the client's order of preference, the CipherSuites supported by the client. The message also contains a random byte string that is used in subsequent computations. The protocol allows for the "client hello to include the data compression methods supported by the client.
2. The SSL or TLS server responds with a "server hello" message that contains the CipherSuite chosen by the server from the list provided by the client, the session ID, and another random byte string. The server also sends its digital certificate. If the server requires a digital certificate for client authentication, the server sends a "client certificate request" that includes a list of the types of certificates supported and the Distinguished Names of acceptable Certification Authorities (CAs).
3. The SSL or TLS client verifies the server's digital certificate.
4. The SSL or TLS client sends the random byte string that enables both the client and the server to compute the secret key to be used for encrypting subsequent message data. The random byte string itself is encrypted with the server's public key.
5. If the SSL or TIS server sent a "client certificate request" the client sends a random byte string encrypted with the client's private key, together with the client's digital certificate or a "no digital certificate alert" This alert is only a warning, but with some implementations the handshake fails if client authentication is mandatory.
6. The SSL or TLS server verifies the client's certificate. 
7. The SSL or TIS client sends the server a "finished" messase, which is encrypted with the secret key indicating that the client part of the handshake is complete.
8. The SSL or TLS server sends the client a "finished" message, which is encrypted with the secret key, indicating that the server part of the handshake is complete.
9. For the duration of the SSL or TLS session, the server and client can now exchange messages that are symetrically encrypted with the shared secret key.


![IBM An overview of the SSL or TLS handshake](https://github.com/MuatazMedini-WolfSSLRepo/wolfssl_android_tls_example_demo/assets/59283470/ae4a13d5-a5f1-421c-b456-b7c05e63cb6d)

<h2> An Overview of Objects used in this project </h2>

In this project, the TLS Handshake and data exchange requires 
1. SSLEngine - Configured as ClientEngine and Server Engine
2. WolfSSLProvider - To use WolfSSL Library for TLS Handshake and data exchange.
3. Keystore
4. Truststore

<h3> SSLEngine </h3>
A class which enables secure communications using protocols such as the Secure Sockets Layer (SSL) or IETF RFC 2246 "Transport Layer Security" (TLS) protocols, but is transport independent.

The primary distinction of an SSLEngine is that it operates on inbound and outbound byte streams, independent of the transport mechanism. 
It is the responsibility of the SSLEngine user to arrange for reliable I/O transport to the peer. By separating the SSL/TLS abstraction from the I/O transport mechanism, the SSLEngine can be used for a wide variety of I/O types, such as non-blocking I/O (polling), selectable non-blocking I/O, Socket and the traditional Input/OutputStreams, local ByteBuffers or byte arrays, future asynchronous I/O models , and so on.

At a high level, the SSLEngine appears thus:
 
                   app data
 
                 |           ^
                 |     |     |
                 v     |     |
            +----+-----|-----+----+
            |          |          |
            |       SSL|Engine    |
    wrap()  |          |          |  unwrap()
            | OUTBOUND | INBOUND  |
            |          |          |
            +----+-----|-----+----+
                 |     |     ^
                 |     |     |
                 v           |
 
                    net data
                    
Application data (also known as plaintext or cleartext) is data which is produced or consumed by an application. Its counterpart is network data, which consists of either handshaking and/or ciphertext (encrypted) data, and destined to be transported via an I/O mechanism. Inbound data is data which has been received from the peer, and outbound data is destined for the peer.

<h4> Using SSLEngine </h4>
1. At first, the TLS Handshake is performed between the Client and the Server followed by which an App data is encrypted by the SSLEngine (configured as a Client) and decrypted by another SSLEngine (configured as a server).
2. If an app data is fed to an SSLEngine prior to the TLS Handshake, the TLS Handshaking is performed by the Client and the server. After the TLS Handshaking is performed, the app data is then encrypted/decrypted by the SSLEngine accordingly.

The net data from the SSLEngine shown in the figure can be sent across Bluetooth Network, Bluetooth Low Enrgy Network or through sockets.

More details on the SSLEngine can be found here:
https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/SSLEngine.html 

<h3> WolfSSLProvider </h3>
A class that loads the WolfSSL JNI Library and instantiates a WolfSSL Object to be used in an Android app.

<h3> Keystore and Truststore </h3>
Java Keystore and Truststore are both used in Java applications for managing digital certificates, specifically in the context of secure communication over SSL/TLS protocols. Let's look at each of them separately:

<h4>Java Keystore </h4>
A Java Keystore (JKS) is a repository where cryptographic keys and certificates can be stored. It is primarily used for server-side applications that require SSL/TLS encryption, such as web servers or application servers. The Keystore is a file protected by a password and is typically stored as a binary file with a ".jks" extension.

In a Java Keystore, you can store the following types of entries:
Private Keys: These are used to prove the server's identity to clients during SSL/TLS negotiation.
Public Key Certificates: These certificates are used to authenticate the identity of other parties, such as clients connecting to the server.
Trusted Certificates: These certificates represent trusted Certificate Authorities (CAs) that are used to validate the authenticity of other certificates.

The Java Keytool command-line utility is commonly used to manage and manipulate the contents of a Java Keystore. With Keytool, you can generate key pairs, import and export certificates, create new keystores, and perform various other operations related to cryptographic keys and certificates.


<h4>Truststore</h4>
A Truststore, on the other hand, is a specific type of Keystore that contains only trusted certificates. It is used by Java applications to determine whether to trust the identity of the parties with whom they communicate. In the context of SSL/TLS, a Truststore contains the certificates of trusted CAs or self-signed certificates that are considered trustworthy.

When a Java application initiates an SSL/TLS connection, it receives the server's certificate during the handshake process. The application then checks whether the received certificate is trusted by verifying it against the certificates stored in the Truststore. If the certificate matches any trusted entry, the connection proceeds; otherwise, it may be rejected.

Similar to the Java Keystore, the Java Keytool utility can be used to manage the Truststore. You can add trusted certificates, remove entries, or view the contents of the Truststore using Keytool commands.


In summary, a Java Keystore is used to store cryptographic keys, private keys, and certificates, while a Truststore is a subset of the Keystore that only contains trusted certificates used for verifying the authenticity of other certificates during SSL/TLS communication.




