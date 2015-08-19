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

import de.measite.minidns.DNSCache;
import de.measite.minidns.DNSClient;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.dnssec.DNSSECClient;
import de.measite.minidns.record.SRV;
import org.jivesoftware.smack.initializer.SmackInitializer;
import org.jivesoftware.smack.util.DNSUtil;
import org.jivesoftware.smack.util.dns.DNSResolver;
import org.jivesoftware.smack.util.dns.SRVRecord;
import org.jxmpp.util.cache.ExpirationCache;

import java.util.LinkedList;
import java.util.List;


/**
 * This implementation uses the <a href="https://github.com/rtreffer/minidns/">minidns</a> implementation for
 * resolving DNS addresses.
 */
public class MiniDnsResolver implements SmackInitializer, DNSResolver {

    private static final long ONE_DAY = 24*60*60*1000;
    private static final MiniDnsResolver instance = new MiniDnsResolver();
    private static final ExpirationCache<Question, DNSMessage> cache = new ExpirationCache<Question, DNSMessage>(10, ONE_DAY);
    private static final DNSCache dnsCache = new DNSCache() {

        @Override
        public DNSMessage get(Question question) {
            return cache.get(question);
        }

        @Override
        public void put(Question question, DNSMessage message) {
            long expirationTime = ONE_DAY;
            for (Record record : message.getAnswers()) {
                if (record.isAnswer(question)) {
                    expirationTime = record.getTtl();
                    break;
                }
            }
            cache.put(question, message, expirationTime);
        }

    };

    public static DNSResolver getInstance() {
        return instance;
    }

    @Override
    public List<SRVRecord> lookupSRVRecords(String name, boolean dnssec) {
        List<SRVRecord> res = new LinkedList<SRVRecord>();
        DNSMessage message = (dnssec ? new DNSSECClient(dnsCache) : new DNSClient(dnsCache)).query(name, TYPE.SRV, CLASS.IN);
        if (message == null) {
            return res;
        }
        for (Record record : message.getAnswers()) {
            SRV srv = (SRV) record.getPayload();
            res.add(new SRVRecord(srv.name, srv.port, srv.priority, srv.weight));
        }
        return res;
    }

    public static void setup() {
        DNSUtil.setDNSResolver(getInstance());
    }

    @Override
    public List<Exception> initialize() {
        setup();
        return null;
    }

}
