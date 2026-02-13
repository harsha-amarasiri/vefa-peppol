/*
 * Copyright 2015-2017 Direktoratet for forvaltning og IKT
 *
 * This source code is subject to dual licensing:
 *
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they
 * will be approved by the European Commission - subsequent
 * versions of the EUPL (the "Licence");
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *
 * See the Licence for the specific language governing
 * permissions and limitations under the Licence.
 */

package network.oxalis.vefa.peppol.lookup.locator;

import lombok.extern.slf4j.Slf4j;
import network.oxalis.vefa.peppol.common.lang.PeppolException;
import network.oxalis.vefa.peppol.common.lang.PeppolInfrastructureException;
import network.oxalis.vefa.peppol.common.lang.PeppolResourceException;
import network.oxalis.vefa.peppol.common.model.ParticipantIdentifier;
import network.oxalis.vefa.peppol.lookup.api.LookupException;
import network.oxalis.vefa.peppol.lookup.api.NotFoundException;
import network.oxalis.vefa.peppol.lookup.util.DynamicHostnameGenerator;
import network.oxalis.vefa.peppol.mode.Mode;
import org.apache.commons.lang3.StringUtils;
import org.xbill.DNS.*;
import org.xbill.DNS.tools.lookup;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class BusdoxLocator extends AbstractLocator {

    private final long timeout;
    private final int maxRetries;
    private final boolean enablePublicDNS;

    private static final List<InetAddress> customDNSServers = new ArrayList<>();
    //Google DNS: faster, supported by multiple data centers all around the world
    public static InetAddress GOOGLE_PRIMARY_DNS;
    public static InetAddress GOOGLE_SECONDARY_DNS;
    //Cloudflare DNS: internet’s fastest DNS directory
    public static InetAddress CLOUDFLARE_PRIMARY_DNS;
    public static InetAddress CLOUDFLARE_SECONDARY_DNS;

    private final DynamicHostnameGenerator hostnameGenerator;

    public BusdoxLocator(Mode mode) {
        this(
                mode.getString("lookup.locator.busdox.prefix"),
                mode.getString("lookup.locator.hostname"),
                mode.getString("lookup.locator.busdox.algorithm"),
                Long.parseLong(mode.getString("lookup.locator.busdox.timeout")),
                Integer.parseInt(mode.getString("lookup.locator.busdox.maxRetries")),
                Boolean.parseBoolean(mode.getString("lookup.locator.busdox.enablePublicDNS"))
        );

        try {
            GOOGLE_PRIMARY_DNS = InetAddress.getByAddress((new byte[]{(byte) (8 & 0xff), (byte) (8 & 0xff), (byte) (8 & 0xff), (byte) (8 & 0xff)}));
            GOOGLE_SECONDARY_DNS = InetAddress.getByAddress((new byte[]{(byte) (8 & 0xff), (byte) (8 & 0xff), (byte) (4 & 0xff), (byte) (4 & 0xff)}));

            CLOUDFLARE_PRIMARY_DNS = InetAddress.getByAddress((new byte[]{(byte) (1 & 0xff), (byte) (1 & 0xff), (byte) (1 & 0xff), (byte) (1 & 0xff)}));
            CLOUDFLARE_SECONDARY_DNS = InetAddress.getByAddress((new byte[]{(byte) (1 & 0xff), (byte) (0 & 0xff), (byte) (0 & 0xff), (byte) (1 & 0xff)}));
        } catch (UnknownHostException e) {
            //Unable to initialize Custom DNS server
        }

        if (enablePublicDNS) {
            customDNSServers.add(GOOGLE_PRIMARY_DNS);
            customDNSServers.add(GOOGLE_SECONDARY_DNS);
            customDNSServers.add(CLOUDFLARE_PRIMARY_DNS);
            customDNSServers.add(CLOUDFLARE_SECONDARY_DNS);
        }
    }

    @SuppressWarnings("unused")
    public BusdoxLocator(String hostname) {
        this("B-", hostname, "MD5", 30L, 3, false);
    }

    public BusdoxLocator(String prefix, String hostname, String algorithm, long timeout, int maxRetries, boolean enablePublicDNS) {
        this.timeout = timeout;
        this.maxRetries = maxRetries;
        this.enablePublicDNS = enablePublicDNS;
        hostnameGenerator = new DynamicHostnameGenerator(prefix, hostname, algorithm);
    }

    @Override
    public URI lookup(ParticipantIdentifier participantIdentifier) throws LookupException {
        // Create hostname for participant identifier.
        String hostname = hostnameGenerator.generate(participantIdentifier);


        try {
            ExtendedResolver extendedResolver = getExtendedResolver(hostname);

            LookupResult result = fetchRecords(hostname, extendedResolver);

            if (result.naptrLookup.getResult() != Lookup.SUCCESSFUL) {
                handleDnsFailure(participantIdentifier, hostname, result.naptrLookup);
            }
        } catch (TextParseException e) {
            throw new LookupException("Error parsing DNS hostname for Busdox lookup:" + e.getMessage(), e);
        } catch (PeppolException e) {
            throw new LookupException("Unexpected exception during Busdox lookup: " + e.getMessage(), e);
        }
        return URI.create(String.format("http://%s", hostname));

    }

    private ExtendedResolver getExtendedResolver(String hostname) {
        ExtendedResolver extendedResolver;
        if (enablePublicDNS) {
            extendedResolver = CustomExtendedDNSResolver.createExtendedResolver(customDNSServers, timeout, maxRetries);
        } else {
            extendedResolver = new ExtendedResolver();
            try {
                if (StringUtils.isNotBlank(hostname)) {
                    extendedResolver.addResolver(new SimpleResolver(hostname));
                }
            } catch (final UnknownHostException ex) {
                //Primary DNS lookup fail, now try with default resolver
            }
            extendedResolver.addResolver(Lookup.getDefaultResolver());
        }
        extendedResolver.setRetries(maxRetries);
        extendedResolver.setTimeout(Duration.ofSeconds(timeout));
        return extendedResolver;
    }

    private static class LookupResult {
        public final Lookup naptrLookup;
        public final Record[] dnsRecords;

        public LookupResult(Lookup naptrLookup, Record[] dnsRecords) {
            this.naptrLookup = naptrLookup;
            this.dnsRecords = dnsRecords;
        }

        public boolean hasRecords() {
            return dnsRecords != null && dnsRecords.length > 0;
        }
    }

    private LookupResult fetchRecords(String hostname, ExtendedResolver extendedResolver) throws TextParseException {
        final Lookup naptrLookup = new Lookup(hostname, Type.NAPTR);
        naptrLookup.setResolver(extendedResolver);

        Record[] dnsRecords;
        int retryCountLeft = maxRetries;
        // Retry, the NAPTR lookup may fail due to a network error. Repeating the lookup might be helpful
        do {
            dnsRecords = naptrLookup.run();
            --retryCountLeft;
        } while (naptrLookup.getResult() == Lookup.TRY_AGAIN && retryCountLeft >= 0);

        // Retry with TCP as well
        if (naptrLookup.getResult() == Lookup.TRY_AGAIN) {
            extendedResolver.setTCP(true);

            retryCountLeft = maxRetries;
            do {
                dnsRecords = naptrLookup.run();
                --retryCountLeft;
            } while (naptrLookup.getResult() == Lookup.TRY_AGAIN && retryCountLeft >= 0);
        }
        return new LookupResult(naptrLookup, dnsRecords);
    }


    private void handleDnsFailure(ParticipantIdentifier participantIdentifier, String hostname, Lookup naptrLookup) throws PeppolException {

        int lookupResult = naptrLookup.getResult();
        String errorString = naptrLookup.getErrorString();

        log.debug("DNS lookup failed with result code {} for hostname '{}': {}", lookupResult, hostname, errorString);

        switch (lookupResult) {
            case Lookup.HOST_NOT_FOUND:
                // Participant not registered in SML - permanent resource failure
                log.info("Participant '{}' not registered in SML: hostname '{}' not found (HOST_NOT_FOUND)",
                        participantIdentifier.getIdentifier(), hostname);
                throw new PeppolResourceException(String.format(
                        "Participant '%s' is not registered in PEPPOL SML. DNS hostname '%s' does not exist.",
                        participantIdentifier.getIdentifier(), hostname));

            case Lookup.TYPE_NOT_FOUND:
                // Participant not registered - DNS host exists but no NAPTR records
                log.info("Participant '{}' not registered in SML: hostname '{}' has no records (TYPE_NOT_FOUND)",
                        participantIdentifier.getIdentifier(), hostname);
                throw new PeppolResourceException(String.format(
                        "Participant '%s' is not registered in PEPPOL SML. DNS hostname '%s' exists but has no records.",
                        participantIdentifier.getIdentifier(), hostname));

            case Lookup.TRY_AGAIN:
                // Transient DNS infrastructure failure - retryable
                log.warn("DNS infrastructure failure for participant '{}' at hostname '{}': {} (TRY_AGAIN)",
                        participantIdentifier.getIdentifier(), hostname, errorString);
                throw new PeppolInfrastructureException(String.format(
                        "SML DNS lookup failed due to network error. DNS hostname: '%s', Error: %s", hostname,
                        errorString != null ? errorString : "Unknown network error"));

            case Lookup.UNRECOVERABLE:
                // DNS/SML configuration error - indicates infrastructure problem
                log.error("DNS unrecoverable error for participant '{}' at hostname '{}': {} (UNRECOVERABLE)",
                        participantIdentifier.getIdentifier(), hostname, errorString);
                throw new PeppolInfrastructureException(String.format(
                        "SML DNS lookup failed due to unrecoverable DNS error. " +
                                "DNS hostname: '%s', Error: %s. This indicates an SML configuration issue.", hostname,
                        errorString != null ? errorString : "Unrecoverable DNS error"));

            default:
                // Unexpected DNS error - treated as infrastructure issue
                log.error("Unexpected DNS error for participant '{}' at hostname '{}': result={}, error={}",
                        participantIdentifier.getIdentifier(), hostname, lookupResult, errorString);
                throw new PeppolInfrastructureException(String.format(
                        "Unexpected DNS error. DNS hostname: '%s', Result code: %d, Error: %s", hostname, lookupResult,
                        errorString != null ? errorString : "Unknown error"));
        }
    }
}
