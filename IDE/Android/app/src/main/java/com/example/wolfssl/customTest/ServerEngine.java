package com.example.wolfssl.customTest;

import com.example.wolfssl.utils.ByteConverter;
import com.example.wolfssl.utils.console;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

public class ServerEngine {
    private static final String TAG = "ServerEngine";
    private final SSLEngine serverEngine;

    public SSLEngineResult.HandshakeStatus status;

    public String provider = "wolfJSSE";
    private String tlsVersion = "TLSv1.2";

    public ServerEngine(InputStream ksInputStream, String ksPass) {
        SSLContext context = getSSLContext(tlsVersion, provider, ksInputStream, ksPass);
        serverEngine = context.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(false);
        status = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    private SSLContext getSSLContext(String protocol, String provider, InputStream ksInputStream, String ksPass) {
        SSLContext context = null;
        try {
            KeyStore ks = KeyStore.getInstance("BKS");
            ks.load(ksInputStream, ksPass.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", provider);
            kmf.init(ks, ksPass.toCharArray());

            context = SSLContext.getInstance(protocol, provider);
            context.init(kmf.getKeyManagers(), null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return context;
    }

    public void beginHandshake() {
        try {
            serverEngine.beginHandshake();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

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

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return status;
    }

    public interface OnDataEncryptedListener {
        public void onDataEncrypted(byte[] tlsData);
    }

    public interface OnDataDecryptedListener {
        public void onDataDecrypted(byte[] tlsData);
    }
}