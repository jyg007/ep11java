package com.example.ep11;

import ep11.Ep11.*;
import ep11.Ep11Mechanisms;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static ep11.Ep11Constants.*;

public final class FullExample {
  private static final byte[] SECP256K1_DER={0x06,0x05,0x2b,(byte)0x81,0x04,0x00,0x0a};
  private static final HexFormat HEX=HexFormat.of();

  private static KeyResult slip10(Client ep,long target,long type,long child,boolean hardened,byte[] base,byte[] chain){
    if(hardened) child += CK_IBM_BTC_BIP0032_HARDENED;
    List<Attribute> tmpl=List.of(
      Attribute.bytes(CKA_EC_PARAMS,SECP256K1_DER), Attribute.bool(CKA_SIGN,true),
      Attribute.bool(CKA_PRIVATE,true), Attribute.bool(CKA_SENSITIVE,true),
      Attribute.bool(CKA_VERIFY,true), Attribute.bool(CKA_DERIVE,true),
      Attribute.ckUlong(CKA_KEY_TYPE,CKK_ECDSA), Attribute.ckUlong(CKA_VALUE_LEN,0),
      Attribute.bool(CKA_IBM_USE_AS_DATA,true));
    BtcDeriveParams p=new BtcDeriveParams(type,child,chain,XCP_BTC_VERSION);
    return ep.deriveKey(target,new CkMechanism(CKM_IBM_BTC_DERIVE,p),base,tmpl);
  }

  public static void main(String[] args){
    Client ep=new Client(); long target=ep.initialize(args.length==0?"3.19":args[0]);
    long[] mechs=ep.getMechanismList(target);
    System.out.printf("Mechanisms (%d):%n",mechs.length);
    for(long m:mechs)System.out.printf("  0x%016x %s%n",m,Ep11Mechanisms.nameOf(m));
    System.out.println("Random: "+HEX.formatHex(ep.generateRandom(target,32)));

    List<Attribute> aesTemplate=List.of(Attribute.ckUlong(CKA_VALUE_LEN,32),Attribute.bool(CKA_UNWRAP,true),Attribute.bool(CKA_WRAP,true),Attribute.bool(CKA_ENCRYPT,true));
    byte[] aes1=ep.generateKey(target,new CkMechanism(CKM_AES_KEY_GEN),aesTemplate).keyBlob();
    System.out.println("AES key blob: "+HEX.formatHex(aes1));
    byte[] reenciphered = ep.reencipher(target, aes1);
    System.out.println("Reenciphered key blob: " + HEX.formatHex(reenciphered));

    byte[] iv=Arrays.copyOf("abcedefghij".getBytes(StandardCharsets.UTF_8),16);
    CkMechanism cbc1=new CkMechanism(CKM_AES_CBC_PAD,iv);
    byte[] cipher=ep.encryptSingle(target,cbc1,aes1,"Hello World!".getBytes(StandardCharsets.UTF_8));
    System.out.println("Cipher: "+HEX.formatHex(cipher));
    System.out.println("Plaintext: "+new String(ep.decryptSingle(target,cbc1,aes1,cipher),StandardCharsets.UTF_8));

    byte[] aes2=ep.generateKey(target,new CkMechanism(CKM_AES_KEY_GEN),aesTemplate).keyBlob();
    CkMechanism cbc2=new CkMechanism(CKM_AES_CBC_PAD,iv);
    byte[] recipher=ep.reencryptSingle(target,cbc1,cbc2,aes1,aes2,cipher);
    System.out.println("ReCipher: "+HEX.formatHex(recipher));
    System.out.println("ReCipher plaintext: "+new String(ep.decryptSingle(target,cbc2,aes2,recipher),StandardCharsets.UTF_8));

    List<Attribute> pubT=List.of(Attribute.bytes(CKA_EC_PARAMS,SECP256K1_DER),Attribute.bool(CKA_VERIFY,true));
    List<Attribute> prvT=List.of(Attribute.bytes(CKA_EC_PARAMS,SECP256K1_DER),Attribute.bool(CKA_SIGN,true),Attribute.bool(CKA_PRIVATE,true),Attribute.bool(CKA_SENSITIVE,true));
    KeyPairResult kp=ep.generateKeyPair(target,new CkMechanism(CKM_EC_KEY_PAIR_GEN),pubT,prvT);
    System.out.println("Private key blob: "+HEX.formatHex(kp.privateKey()));
    System.out.println("Public key blob: "+HEX.formatHex(kp.publicKey()));
    byte[] message="hello world!".getBytes(StandardCharsets.UTF_8);
    CkMechanism ecdsa=new CkMechanism(CKM_ECDSA);
    byte[] sig=ep.signSingle(target,ecdsa,kp.privateKey(),message);
    System.out.println("Signature: "+HEX.formatHex(sig));
    ep.verifySingle(target,ecdsa,kp.publicKey(),message,sig);
    System.out.println("Signature is valid");
    try {ep.verifySingle(target,ecdsa,kp.publicKey(),"Hello world!".getBytes(StandardCharsets.UTF_8),sig);System.out.println("Unexpected: altered message verified");}
    catch(Ep11Exception e){System.out.println("Altered-message verification failed as expected: "+e.getMessage());}

    byte[] wrapped=ep.wrapKey(target,new CkMechanism(CKM_AES_CBC_PAD,iv),aes1,aes2);
    System.out.println("Wrapped key: "+HEX.formatHex(wrapped));
    List<Attribute> unwrapT=List.of(Attribute.ckUlong(CKA_KEY_TYPE,CKK_AES),Attribute.ckUlong(CKA_VALUE_LEN,32),Attribute.bool(CKA_UNWRAP,true),Attribute.bool(CKA_WRAP,true),Attribute.bool(CKA_ENCRYPT,true));
    KeyResult unwrapped=ep.unwrapKey(target,new CkMechanism(CKM_AES_CBC_PAD,iv),aes1,wrapped,unwrapT);
    System.out.println("Unwrapped key blob: "+HEX.formatHex(unwrapped.keyBlob()));

    byte[] seed;
    String master=System.getenv("MASTERSEED");
    if(master!=null&&!master.isBlank()) seed=HEX.parseHex(master.trim());
    else {
      List<Attribute> seedT=List.of(Attribute.ckUlong(CKA_VALUE_LEN,32),Attribute.bool(CKA_VERIFY,true),Attribute.bool(CKA_DERIVE,true),Attribute.bool(CKA_SIGN,true),Attribute.ckUlong(CKA_KEY_TYPE,CKK_GENERIC_SECRET),Attribute.ckUlong(CKA_CLASS,CKO_SECRET_KEY),Attribute.bool(CKA_EXTRACTABLE,false),Attribute.bool(CKA_IBM_USE_AS_DATA,true));
      seed=ep.generateKey(target,new CkMechanism(CKM_GENERIC_SECRET_KEY_GEN),seedT).keyBlob();
      System.out.println("Seed key blob: "+HEX.formatHex(seed));
    }
    KeyResult masterKey=slip10(ep,target,CK_IBM_BTC_SLIP0010_MASTERK,0,false,seed,null);
    System.out.println("Derived master key: "+HEX.formatHex(masterKey.keyBlob()));
    System.out.println("Master chain code: "+HEX.formatHex(masterKey.checksum()));
    KeyResult child=slip10(ep,target,CK_IBM_BTC_SLIP0010_PRV2PRV,1,true,masterKey.keyBlob(),masterKey.checksum());
    System.out.println("Derived child private: "+HEX.formatHex(child.keyBlob()));
    System.out.println("Child chain code: "+HEX.formatHex(child.checksum()));
    KeyResult childPub=slip10(ep,target,CK_IBM_BTC_SLIP0010_PRV2PUB,1,true,masterKey.keyBlob(),masterKey.checksum());
    System.out.println("Derived child public: "+HEX.formatHex(childPub.keyBlob()));
    System.out.println("Child-public chain code: "+HEX.formatHex(childPub.checksum()));
  }
}
