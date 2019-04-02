package com.example;

import com.helger.as2lib.client.AS2Client;
import com.helger.as2lib.client.AS2ClientRequest;
import com.helger.as2lib.client.AS2ClientResponse;
import com.helger.as2lib.client.AS2ClientSettings;
import com.helger.as2lib.crypto.ECompressionType;
import com.helger.as2lib.crypto.ECryptoAlgorithmCrypt;
import com.helger.as2lib.crypto.ECryptoAlgorithmSign;
import com.helger.as2lib.disposition.DispositionOptions;
import com.helger.as2lib.util.dump.HTTPIncomingDumperStreamBased;
import com.helger.as2lib.util.dump.HTTPOutgoingDumperStreamBased;
import com.helger.as2lib.util.http.HTTPHelper;
import com.helger.commons.io.stream.NonClosingOutputStream;
import com.helger.commons.mime.CMimeType;
import com.helger.mail.cte.EContentTransferEncoding;
import com.helger.security.keystore.EKeyStoreType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.Proxy;

public class App {


    private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) throws Exception {
        LOGGER.info("Starting App");
        Proxy aHttpProxy = null;
        if (false)
            aHttpProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("1.2.3.4", 8080));

        if (false)
            HTTPHelper.setHTTPOutgoingDumperFactory(x -> new HTTPOutgoingDumperStreamBased(System.out));
        if (false)
            HTTPHelper.setHTTPIncomingDumperFactory(() -> new HTTPIncomingDumperStreamBased(new NonClosingOutputStream(System.out)));

        // Start client configuration
        final AS2ClientSettings aSettings = new AS2ClientSettings();
        aSettings.setKeyStore(EKeyStoreType.PKCS12, new File("as2_certs.p12"), "testas2");

        // Fixed sender
        aSettings.setSenderData("PartnerA_OID", "as2msgs@partnera.com", "partnera");

        // Fixed receiver - key alias must be "mendelsontestAS2"
        aSettings.setReceiverData("MyCompany_OID",
                "mycompany",
                "http://localhost:10080");
        //final X509Certificate aReceiverCertificate = AS2KeyStoreHelper.readX509Certificate("src/test/resources/mendelson/key2.cer");
        //aSettings.setReceiverCertificate(aReceiverCertificate);

        // AS2 stuff
        aSettings.setPartnershipName(aSettings.getSenderAS2ID() + "_" + aSettings.getReceiverAS2ID());
        // When a signed message is used, the algorithm for MIC and message must be
        // identical
        final ECryptoAlgorithmSign eSignAlgo = ECryptoAlgorithmSign.DIGEST_SHA_256;
        final ECryptoAlgorithmCrypt eCryptAlgo = ECryptoAlgorithmCrypt.CRYPT_AES256_CBC;
        final ECompressionType eCompress = ECompressionType.ZLIB;
        final boolean bCompressBeforeSigning = AS2ClientSettings.DEFAULT_COMPRESS_BEFORE_SIGNING;

        aSettings.setMDNOptions(new DispositionOptions().setMICAlg(eSignAlgo)
                .setMICAlgImportance(DispositionOptions.IMPORTANCE_REQUIRED)
                .setProtocol(DispositionOptions.PROTOCOL_PKCS7_SIGNATURE)
                .setProtocolImportance(DispositionOptions.IMPORTANCE_REQUIRED));

        aSettings.setEncryptAndSign(eCryptAlgo, eSignAlgo);
        aSettings.setCompress(eCompress, bCompressBeforeSigning);
        aSettings.setMessageIDFormat("$date.ddMMuuuuHHmmssZ$-$rand.1234$@$msg.sender.as2_id$_$msg.receiver.as2_id$");
        aSettings.setRetryCount(1);
        aSettings.setConnectTimeoutMS(10_000);
        aSettings.setReadTimeoutMS(10_000);
        aSettings.setLargeFileSupport(false);

        // Build client request
        final AS2ClientRequest aRequest = new AS2ClientRequest("AS2 test message from as2-lib");
        aRequest.setData(new DataHandler(new FileDataSource(new File("cars.xml"))));
        aRequest.setContentType(CMimeType.TEXT_PLAIN.getAsString());
        aRequest.setContentTransferEncoding(EContentTransferEncoding.BINARY);

        // Send message
        final AS2ClientResponse aResponse = new AS2Client().setHttpProxy(aHttpProxy)
                .sendSynchronous(aSettings, aRequest);
        if (aResponse.hasException())
            LOGGER.info(aResponse.getAsString());

        LOGGER.info("Done");
    }
}
