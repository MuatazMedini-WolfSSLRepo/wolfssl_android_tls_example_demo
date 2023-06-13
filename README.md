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



<h2> Project Implementation </h2>
This project supports only one way authentication (SSL Handshake) ie: The TLS Client authenticates a TLS server by verifying the server's certificate (chain of trust).
The TLS server authentication of the TLS Client will be added later.

The file structure of the Project is <project_directory>/Projects/wolfssl_android_tls_example_demo/IDE/Android

Open the "Android" project mentioned at the end of the file structure.

<h3> WolfSSL Initialization </h3>
Declare the following codes in the MainActivity.java file

1. The WolfSSLProvider is instantiated to access and use the WolfSSL Library. It is declared in the MainActivity.

``` 
// Add the WolfSSLProvider here
Security.addProvider(new WolfSSLProvider()); 
```

To enable WolfSSL Debug logs, use this code.

```    
// Enable WolfSSL Debug Logs here
System.setProperty("wolfjsse.debug", "true");
```

The Keystore and truststore used in this project is in BKS format as the Android doesn't support the keystore and truststore in the JKS format. 
You can use the code below in your terminal to convert the keystore and truststore from JKS to BKS format:

```
keytool -importkeystore -srckeystore keystore.jks -srcstoretype JKS -destkeystore keystore.bks -deststoretype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath <BountyCastleJarFilePath>/bcprov-jdk15on-1.52.jar
```

```
keytool -importkeystore -srckeystore truststore.jks -srcstoretype JKS -destkeystore truststore.bks -deststoretype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath <BountyCastleJarFilePath>/bcprov-jdk15on-1.52.jar
```

The Keystore and Truststore are added in "raw" resource folder as shown in the figure below:
![Screenshot 2023-06-13 at 11 17 18 AM](https://github.com/MuatazMedini-WolfSSLRepo/wolfssl_android_tls_example_demo/assets/59283470/1cefa954-f848-41bd-804e-6808e359abc5)


2. The Keystore and Truststore present are accessed from the "raw" resource folder by using the InputSream.

```
int keystoreRes = R.raw.keystore;
int truststoreRes = R.raw.truststore;
String ksPass = "wolfssl";
String tsPass = "wolfssl";
InputStream ksInputStream = getResources().openRawResource(keystoreRes);
InputStream tsInputStream = getResources().openRawResource(truststoreRes);
```

  The Keystore and the Truststore require a password to access the server-certificate and server-private key in the keystore and the ca-certificate (used to sign the server certificate) in the Truststore  respectively.

3. The ClientEngine is instantiated by passing the Truststore to the ClientEngine's constructor. The TLS Client uses Truststore to authenticate the TLS Server by verifiying the Server-certificate.
```
clientEngine = new ClientEngine(tsInputStream, tsPass);
```

  The ServerEngine is instantiated by passing the Keystore to the ServerEngine's constructor. The TLS Server uses Keystore to store the server-certificate and the server-private-key.
```
serverEngine = new ServerEngine(ksInputStream, ksPass);
```
4. Begin the TLS Handshake process when "Start TLS Handshake" button is clicked.
```
// Begin SSL Handshake
serverEngine.beginHandshake();
clientEngine.beginHandshake();
```

5. The following codes perform the TLS Handshake between the Client and the Server.
   Here, for simplicity I am using memory buffers (byte array) to get the TLS Handshake Data from the ClientEngine and parsing the TLS Handshake in the ServerEngine and vice-versa. 
   The TLS Data generated can be transported across the Bluetooth network, Bluetooth Low Energy Network or through Sockets.

```
try {
            buttonStartConnection.setEnabled(false);

            InputStream ksInputStream = getResources().openRawResource(keystoreRes);
            InputStream tsInputStream = getResources().openRawResource(truststoreRes);

            clientEngine = new ClientEngine(tsInputStream, tsPass);
            serverEngine = new ServerEngine(ksInputStream, ksPass);

            // Begin SSL Handshake
            serverEngine.beginHandshake();
            clientEngine.beginHandshake();

            // Step 1 : Generate TLS Handshake CLIENT-HELLO Data (Client to Server)
            clientEngine.encryptData(new byte[]{}, tlsClientHelloData -> {
                /*
                 *  tlsClientHelloData can be wrapped into another data packet and sent to the device configured as a TLS Server either
                 *  through Bluetooth Network, Bluetooth Low Energy Network, or through Sockets.
                 */
                console.log(TAG, ByteConverter.getHexStringFromByteArray(tlsClientHelloData, true));

                    /*
                        The device configured as a TLS Server receives the data from the client. The data received is parsed as a TLS Server.
                        Note : The data is not decrypted as it is a TLS Handshake Data
                     */
                serverEngine.decryptData(tlsClientHelloData, null);


                // Step 2 : Generate TLS Handshake SERVER-HELLO Data - (Server to Client)
                serverEngine.encryptData(new byte[]{}, tlsServerHelloData -> {
                    /*
                     *  tlsServerHelloData can be wrapped into another data packet and sent to the device configured as a TLS Client either
                     *  through Bluetooth Network, Bluetooth Low Energy Network, or through Sockets.
                     */
                    console.log(TAG, ByteConverter.getHexStringFromByteArray(tlsServerHelloData, true));

                        /*
                        The end-device receives the data from the client. The data received by the end-device is parsed as a TLS Server.
                        Note : The data is not decrypted as it is a TLS Handshake Data
                        */
                    clientEngine.decryptData(tlsServerHelloData, null);


                    // Step 3 : Generate TLS Handshake CLIENT-CHANGE-CIPHER-SPEC Data (Client to Server)
                    clientEngine.encryptData(new byte[]{}, tlsChangeClientCipherSpecData -> {
                        /*
                         *  tlsChangeClientCipherSpecData can be wrapped into another data packet and sent to the device configured as a TLS Server either
                         *  through Bluetooth Network, Bluetooth Low Energy Network, or through Sockets.
                         */
                        console.log(TAG, ByteConverter.getHexStringFromByteArray(tlsChangeClientCipherSpecData, true));

                            /*
                                The end-device receives the data from the client. The data received by the end-device is parsed as a TLS Server.
                                Note : The data is not decrypted as it is a TLS Handshake Data
                            */
                        serverEngine.decryptData(tlsChangeClientCipherSpecData, null);

                        // Step 4 : Generate TLS Handshake SERVER-CHANGE-CIPHER-SPEC Data (Server to Client)
                        serverEngine.encryptData(new byte[]{}, tlsHandshakeServerCipherSpec -> {
                            /*
                             *  tlsHandshakeServerCipherSpec can be wrapped into another data packet and sent to the device configured as a TLS Client either
                             *  through Bluetooth Network, Bluetooth Low Energy Network, or through Sockets.
                             */
                            console.log(TAG, ByteConverter.getHexStringFromByteArray(tlsHandshakeServerCipherSpec, true));

                            clientEngine.decryptData(tlsHandshakeServerCipherSpec, null);
                            if (clientEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                                    clientEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                                if (serverEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                                        serverEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                                    console.log(TAG, "TLS Handshake Complete");

                                    buttonSendAppData.setEnabled(false);
                                    buttonSendAppData.setEnabled(true);
                                }
                            }
                        });
                    });
                });
            });
        } catch (Exception e) {
            e.printStackTrace();
            buttonStartConnection.setEnabled(true);
            buttonSendAppData.setEnabled(false);
        }
```

6. The "Start TLS Handshake" button is disabled after the TLS Handshake is successful between the TLS Client and the TLS Server. 
   The "Begin Sending App Data" button is enabled after the TLS HAndshake is completed.
   
  In this implementation: 
  The Client App Data is encrypted by the ClientEngine to generate a TLS Client App Data. This TLS Client App Data is decrypted at the ServerEngine.
  The Server App Data is encrypted by the ServerEngine to generate a TLS Server App Data. This TLS Server App Data is decrypted at the ClientEngine.
  
  The following code is shown below:
```
buttonSendAppData.setOnClickListener(v -> {
            /*
                1. As an example, the TLS Client sends an app data to the TLS Server. The TLS Server then parses the data sent by the TLS Client.
                2. The TLS Server then sends an app data to the TLS Client. The TLS Client then parses the data sent by the TLS Server.
             */
            byte[] clientAppData = "Hi. This is the message from the TLS Client".getBytes(StandardCharsets.UTF_8);
            byte[] serverAppData = "Hi. This is the message from the TLS Server".getBytes(StandardCharsets.UTF_8);

            console.log(TAG, "Client App Data = " + ByteConverter.getHexStringFromByteArray(clientAppData, true));
            console.log(TAG, "Server App Data = " + ByteConverter.getHexStringFromByteArray(serverAppData, true));
            // Begin Sending App Data to the server
            clientEngine.encryptData(clientAppData, new ClientEngine.OnDataEncryptedListener() {
                @Override
                public void onDataEncrypted(byte[] tlsClientAppData) {
                    // Send the TLS Client App Data to the Server
                    console.log(TAG, "TLS Client App Data = " + ByteConverter.getHexStringFromByteArray(tlsClientAppData, true));

                    // Parse the TLS Client App Data sent by the Client in the TLS Server
                    serverEngine.decryptData(tlsClientAppData, tlsAppData -> {
                        console.log(TAG, "TLS Client App Data parsed by the server = " + ByteConverter.getHexStringFromByteArray(tlsAppData, true));
                        console.log(TAG, "TLS Client App Decrypted Message = " + new String(tlsAppData, StandardCharsets.UTF_8));

                        serverEngine.encryptData(serverAppData, new ServerEngine.OnDataEncryptedListener() {
                            @Override
                            public void onDataEncrypted(byte[] tlsServerAppData) {
                                // Send the TLS Server App Data to the Client
                                console.log(TAG, "TLS Server App Data = " + ByteConverter.getHexStringFromByteArray(tlsServerAppData, true));

                                // Parse the TLS Server App Data sent by the Server in the TLS Client
                                clientEngine.decryptData(tlsServerAppData, new ClientEngine.OnDataDecryptedListener() {
                                    @Override
                                    public void onDataDecrypted(byte[] tlsAppData) {
                                        console.log(TAG, "TLS Server App Data parsed by the client = " + ByteConverter.getHexStringFromByteArray(tlsAppData, true));
                                        console.log(TAG, "TLS Server App Decrypted Message = " + new String(tlsAppData, StandardCharsets.UTF_8));
                                    }
                                });
                            }
                        });
                    });
                }
            });
        });
```

<h2> Overview of ClientEngine and ServerEngine used in this Project </h2>
The ClientEngine and ServerEngine are the classes responsible for performing TLS Handshake, encrypting and decrypting data respectively.

<h3>SSLContext</h3>
To use SSLEngine we require a SSLContext Object. The SSLContext is a factory class for creating a Secure Socket Object or a SSL Engine Object.

<h3> ClientEngine </h3>
The ClientEngine consists of ByteBuffers to hold plain and TLS data respectively, and a SSLEngine.

To get SSLContext, we need TrustStore and TrustManagers to configure as a TLS Client.

1. First, instantate a Truststore object and add truststore.bks file into that object. 

```
KeyStore ts = KeyStore.getInstance("BKS");
ts.load(tsInputStream, tsPass.toCharArray());
```
2. Get the instance of the TrustManagerFactory which manages the Truststore

```
public String provider = "wolfJSSE";
TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", provider);
tmf.init(ts);
```
Here, we are setting "wolfJSSE" as a provider to get the TrustManagerFactory.

3. Get the SSLContext instance and initialize the SSLContext with the TrustManages

```
public String provider = "wolfJSSE";
private String tlsVersion = "TLSv1.2";
context = SSLContext.getInstance(protocol, provider);
context.init(null, tmf.getTrustManagers(), null);
```

4. Get the SSLEngine from the SSLContext and configure the SSLEngine as a TLSClient

```
SSLContext context = getSSLContext(tlsVersion, provider, tsInputStream, tsPass);
SSLEngine clientEngine = context.createSSLEngine();
clientEngine.setUseClientMode(true);
status = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
```

5. Use the SSLEngine to generate or encrypt the Client TLS Handshake or App Data and parse the Server TLS Handshake or decrypt App Data respectively.
```
public void encryptData(byte[] data, OnDataEncryptedListener callback) {
        SSLEngineResult result = null;

        try {
            ByteBuffer input = ByteBuffer.allocate(data.length);
            input.put(data);
            input.flip();

            ByteBuffer output = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
            status = clientEngine.getHandshakeStatus();
            console.log(TAG, "Client Status = " + status.toString());

            result = clientEngine.wrap(input, output);
            console.log(TAG,
                    "Client Wrap : " +
                            "Consumed = " + result.bytesConsumed() +
                            "Produced = " + result.bytesProduced() +
                            "Status = " + result.getStatus().name());


            while (clientEngine.getDelegatedTask() != null) {
                clientEngine.getDelegatedTask().run();
            }

            status = clientEngine.getHandshakeStatus();
            console.log(TAG, "Client Status = " + status.toString());

            if (result.bytesProduced() > 0) {
                output.flip();

                do { /*Send All Data*/
                    byte[] outputData = new byte[output.remaining()];
                    output.get(outputData);

                    console.log(TAG, "Wrapped Data = " + ByteConverter.getHexStringFromByteArray(outputData, true));

                    // Sending TLS Data through callback
                    if (callback != null) {
                        callback.onDataEncrypted(outputData);
                    }
                } while (output.remaining() > 0);
                output.compact();
            }
            status = result.getHandshakeStatus();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```

```
public void decryptData(byte[] encryptedData, OnDataDecryptedListener callback) {
        SSLEngineResult result = null;
        try {
            status = clientEngine.getHandshakeStatus();

            ByteBuffer input = ByteBuffer.allocate(encryptedData.length);
            input.put(encryptedData);
            input.compact();

            ByteBuffer output = ByteBuffer.allocateDirect(clientEngine.getSession().getPacketBufferSize());
            console.log(TAG, "Unwrap Data");
            result = clientEngine.unwrap(input, output);
            status = result.getHandshakeStatus();

            console.log(TAG, "Client unwrap : " +
                    "Consumed = " + result.bytesConsumed() +
                    "Produced = " + result.bytesProduced() +
                    "Status = " + result.getStatus().name());

            while (clientEngine.getDelegatedTask() != null) {
                clientEngine.getDelegatedTask().run();
            }

            output.flip();

            byte[] decryptedData = new byte[output.remaining()];
            output.get(decryptedData);

            // Sending decrypted Data through callback
            if (callback != null) {
                callback.onDataDecrypted(decryptedData);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```

<h3> ServerEngine </h3>
The ServerEngine consists of ByteBuffers to hold plain and TLS data respectively, and a SSLEngine.

To get SSLContext, we need Keystore and KeyManagers to configure as a TLS Server.

1. First, instantate a Keystore object and add keystore.bks file into that object. 

```
KeyStore ks = KeyStore.getInstance("BKS");
ks.load(tsInputStream, ksPass.toCharArray());
```
2. Get the instance of the TrustManagerFactory which manages the Truststore

```
public String provider = "wolfJSSE";
KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", provider);
kmf.init(ks, ksPass.toCharArray());
```
Here, we are setting "wolfJSSE" as a provider to get the TrustManagerFactory.

3. Get the SSLContext instance and initialize the SSLContext with the TrustManages

```
public String provider = "wolfJSSE";
private String tlsVersion = "TLSv1.2";
context = SSLContext.getInstance(protocol, provider);
context.init(kmf.getTrustManagers, null, null);
```

4. Get the SSLEngine from the SSLContext and configure the SSLEngine as a TLSClient

```
SSLContext context = getSSLContext(tlsVersion, provider, ksInputStream, ksPass);
serverEngine = context.createSSLEngine();
serverEngine.setUseClientMode(false);
serverEngine.setNeedClientAuth(false);
status = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
```

5. Use the SSLEngine to generate or encrypt the Server TLS Handshake or App Data and parse the Client TLS Handshake or decrypt App Data respectively.

```
public void encryptData(byte[] data, OnDataEncryptedListener callback) {
        SSLEngineResult result = null;
        try {
            ByteBuffer input = ByteBuffer.allocate(data.length);
            input.put(data);
            input.flip();

            ByteBuffer output = ByteBuffer.allocate(serverEngine.getSession().getPacketBufferSize());

            status = serverEngine.getHandshakeStatus();
            console.log(TAG, "Server Status = " + status.toString());

            result = serverEngine.wrap(input, output);

            console.log(TAG, "Server Wrap : " +
                    "Consumed = " + result.bytesConsumed() +
                    "Produced = " + result.bytesProduced() +
                    "Status = " + result.getStatus().name());

            while (serverEngine.getDelegatedTask() != null) {
                serverEngine.getDelegatedTask().run();
            }

            status = serverEngine.getHandshakeStatus();
            console.log(TAG, "Server Status = " + status.toString());

            if (result.bytesProduced() > 0) {
                output.flip();

                do {/* Send All Data*/
                    byte[] outputData = new byte[output.remaining()];
                    output.get(outputData);

                    console.log(TAG, "Wrapped Data = " + ByteConverter.getHexStringFromByteArray(outputData, true));

                    // Sending encrypted data through callback
                    if (callback != null) {
                        callback.onDataEncrypted(outputData);
                    }
                } while (output.remaining() > 0);
                output.compact();
            }
            status = result.getHandshakeStatus();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

```

```
public void decryptData(byte[] tlsData, OnDataDecryptedListener callback) {
        SSLEngineResult result = null;
        try {
            status = serverEngine.getHandshakeStatus();

            ByteBuffer input = ByteBuffer.allocate(tlsData.length);
            input.put(tlsData);
            input.compact();

            ByteBuffer output = ByteBuffer.allocateDirect(serverEngine.getSession().getPacketBufferSize());
            console.log(TAG, "Unwrap Data");
            result = serverEngine.unwrap(input, output);
            status = result.getHandshakeStatus();

            console.log(TAG, "Server Unwrap : " +
                    "Consumed = " + result.bytesConsumed() +
                    "Produced = " + result.bytesProduced() +
                    "Status = " + result.getStatus().name());

            while (serverEngine.getDelegatedTask() != null) {
                serverEngine.getDelegatedTask().run();
            }

            output.flip();

            byte[] decryptedData = new byte[output.remaining()];
            output.get(decryptedData);

            // Sending decrypted data through callback
            if (callback != null) {
                callback.onDataDecrypted(decryptedData);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```

This implementation demonstrates using the ClientEngine and the ServerEngine to perform SSL/TLS Handshake, encrypt and decrypt TLS App data.


Please feel free to contact me at andro.medini07@gmail.com for any doubts or assistance.


