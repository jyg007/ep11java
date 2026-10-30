package com.example.ep11;

import java.util.HexFormat;
import java.util.List;

import ep11.Ep11Mechanisms;

import static ep11.Ep11.*;
import static ep11.Ep11Constants.*;

public final class Main {
    public static void main(String[] args) {
        String adapterDomain = args.length == 0 ? "3.19" : args[0];

        try {
            Client ep11 = new Client();
            long target = ep11.initialize(adapterDomain);
            System.out.printf("Target: 0x%016x%n", target);

            long[] mechanisms = ep11.getMechanismList(target);
            System.out.printf("Mechanisms (%d):%n", mechanisms.length);
            for (long mechanism : mechanisms) {
                System.out.printf("  0x%016x  %s%n", mechanism,
                        Ep11Mechanisms.nameOf(mechanism));
            }

            byte[] random = ep11.generateRandom(target, 32);
            System.out.println("Random data: " + HexFormat.of().formatHex(random));

            CkMechanism mechanism = new CkMechanism(CKM_AES_KEY_GEN);
            List<Attribute> keyTemplate = List.of(
                    Attribute.ckUlong(CKA_VALUE_LEN, 32),
                    Attribute.bool(CKA_UNWRAP, true),
                    Attribute.bool(CKA_WRAP, true),
                    Attribute.bool(CKA_ENCRYPT, true)
            );

            KeyResult generated = ep11.generateKey(target, mechanism, keyTemplate);
            System.out.printf("Generated EP11 AES-256 key blob (%d bytes): %s%n",
                    generated.keyBlob().length,
                    HexFormat.of().formatHex(generated.keyBlob()));
            System.out.printf("Checksum (%d bytes): %s%n",
                    generated.checksum().length,
                    HexFormat.of().formatHex(generated.checksum()));

        } catch (Throwable e) {
            System.err.println("EP11 test failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
