package com.example.wolfssl.customTest;

import com.example.wolfssl.utils.ByteConverter;
import com.example.wolfssl.utils.console;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

public class ClientEngine {
    private static final String TAG = "ClientEngine";

    public String provider = "wolfJSSE";
    private String tlsVersion = "TLSv1.2";

    private SSLEngine clientEngine = null;
    private SSLEngineResult.HandshakeStatus status = null;

    public ClientEngine(InputStream tsInputStream, String tsPass) {
        SSLContext context = getSSLContext(tlsVersion, provider, tsInputStream, tsPass);
        clientEngine = context.createSSLEngine();
        clientEngine.setUseClientMode(true);
        status = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    private SSLContext getSSLContext(String protocol, String provider, InputStream tsInputStream, String tsPass) {
        SSLContext context = null;
        try {
            KeyStore ts = KeyStore.getInstance("BKS");
            ts.load(tsInputStream, tsPass.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", provider);
            tmf.init(ts);

            context = SSLContext.getInstance(protocol, provider);
            context.init(null, tmf.getTrustManagers(), null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return context;
    }

    public void beginHandshake() {
        if (clientEngine != null) {
            try {
                clientEngine.beginHandshake();
            } catch (SSLException e) {
                throw new RuntimeException(e);
            }
        }
    }

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

    public SSLEngineResult.HandshakeStatus getHandshakeStatus(){
        return status;
    }

    public interface OnDataEncryptedListener {
        public void onDataEncrypted(byte[] tlsData);
    }

    public interface OnDataDecryptedListener {
        public void onDataDecrypted(byte[] tlsData);
    }
}