/**
 *
 * Copyright 2014 Florian Schmaus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smack.util.dns.minidns;

import de.measite.minidns.dane.DaneVerifier;
import de.measite.minidns.dane.ExpectingTrustManager;
import org.jivesoftware.smack.initializer.SmackInitializer;
import org.jivesoftware.smack.util.DNSUtil;
import org.jivesoftware.smack.util.dns.DaneProvider;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.List;

public class MiniDnsDaneProvider implements SmackInitializer, DaneProvider {
    private final DaneVerifier verifier;
    private ExpectingTrustManager expectingTrustManager;

    public MiniDnsDaneProvider() {
        this(new DaneVerifier());
    }

    public MiniDnsDaneProvider(DaneVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public DaneProvider newInstance() {
        return new MiniDnsDaneProvider(verifier);
    }

    @Override
    public void init(SSLContext context, KeyManager[] km, X509TrustManager tm, SecureRandom random) throws KeyManagementException {
        if (expectingTrustManager != null) {
            throw new IllegalStateException("DaneProvider was initialized before. Use newInstance() instead.");
        }
        expectingTrustManager = new ExpectingTrustManager(tm);
        context.init(km, new TrustManager[]{expectingTrustManager}, random);
    }

    @Override
    public void finish(SSLSocket sslSocket) throws CertificateException {
        if (!verifier.verify(sslSocket) && expectingTrustManager.hasException()) {
            try {
                sslSocket.close();
            } catch (IOException ignored) {
                // We'll throw a better exception anyway.
            }
            throw expectingTrustManager.getException();
        }
    }

    @Override
    public List<Exception> initialize() {
        DNSUtil.setDaneProvider(this);
        return null;
    }
}
