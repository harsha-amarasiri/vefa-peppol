package network.oxalis.vefa.peppol.common.lang;

import lombok.NonNull;

public class PeppolResourceException extends PeppolException {

    public PeppolResourceException(String message) {
        super(message);
    }

    public PeppolResourceException(Throwable cause) {
        super(cause);
    }

    public PeppolResourceException(String message, Throwable cause) {
        super(message, cause);
    }
}
