/* MainActivity.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


package com.example.wolfssl;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.example.wolfssl.customTest.ClientEngine;
import com.example.wolfssl.customTest.ServerEngine;
import com.example.wolfssl.utils.ByteConverter;
import com.example.wolfssl.utils.console;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLX509;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

public class MainActivity extends AppCompatActivity {

    private Button buttonStartConnection, buttonSendAppData;
    private ClientEngine clientEngine;
    private ServerEngine serverEngine;
    private static final int keystoreRes = R.raw.keystore;
    private static final int truststoreRes = R.raw.truststore;
    private static final String ksPass = "wolfssl";
    private static final String tsPass = "wolfssl";
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        buttonStartConnection = findViewById(R.id.buttonStartConnection);
        buttonSendAppData = findViewById(R.id.buttonSendAppData);

        // Enable WolfSSL Debug Logs here
//        System.setProperty("wolfjsse.debug", "true");
        // Add the WolfSSLProvider here
        Security.addProvider(new WolfSSLProvider());

        buttonSendAppData.setEnabled(false);
        buttonStartConnection.setEnabled(true);

        buttonStartConnection.setOnClickListener(v -> {
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

                                clientEngine.decryptData(tlsHandshakeServerCipherSpec,null);
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
        });

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
                        console.log(TAG,"TLS Client App Decrypted Message = "+ new String(tlsAppData, StandardCharsets.UTF_8));

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
                                        console.log(TAG,"TLS Server App Decrypted Message = "+ new String(tlsAppData, StandardCharsets.UTF_8));
                                    }
                                });
                            }
                        });
                    });
                }
            });
        });
    }
}