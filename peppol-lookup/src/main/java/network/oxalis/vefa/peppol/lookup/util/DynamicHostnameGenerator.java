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

package network.oxalis.vefa.peppol.lookup.util;

import com.google.common.io.BaseEncoding;
import network.oxalis.vefa.peppol.common.lang.PeppolRuntimeException;
import network.oxalis.vefa.peppol.common.model.ParticipantIdentifier;
import network.oxalis.vefa.peppol.lookup.api.LookupException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class DynamicHostnameGenerator {

    static {
        // Make sure to register Bouncy Castle as a provider.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    private BaseEncoding encoding;

    /**
     * Prefix for generated hostname.
     */
    private String prefix;

    /**
     * Base hostname for lookup.
     */
    private String hostname;

    /**
     * Algorithm used for geneation of hostname.
     */
    private String digestAlgorithm;

    public DynamicHostnameGenerator(String prefix, String hostname, String digestAlgorithm) {
        this(prefix, hostname, digestAlgorithm, BaseEncoding.base16());
    }

    public DynamicHostnameGenerator(String prefix, String hostname, String digestAlgorithm, BaseEncoding encoding) {
        this.prefix = prefix;
        this.hostname = hostname;
        this.digestAlgorithm = digestAlgorithm;
        this.encoding = encoding;
    }

    public String generate(ParticipantIdentifier participantIdentifier) throws PeppolRuntimeException {
        try {
            // Create digest based on participant identifier.
            MessageDigest md = MessageDigest.getInstance(digestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            byte[] digest = md.digest(participantIdentifier.getIdentifier().getBytes(StandardCharsets.UTF_8));

            // Create hex of digest.
            String receiverHash = encoding.encode(digest).toLowerCase();

            return String.format("%s%s.%s.%s", prefix, receiverHash, participantIdentifier.getScheme().getIdentifier(), hostname);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PeppolRuntimeException("Error occurred generating hostname for " + participantIdentifier, e);
        }
    }
}
