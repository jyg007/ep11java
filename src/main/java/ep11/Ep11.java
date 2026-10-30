package ep11;

import com.sun.jna.*;
import com.sun.jna.ptr.LongByReference;
import java.util.*;

public final class Ep11 {
  private Ep11() {}
  public static final long CKR_OK=0, XCP_TGT_INIT=-1L;
  public static final int XCP_MOD_VERSION=2, MAX_FNAME_CHARS=256, MAX_BLOB_SIZE=9126, MAX_CSUM_SIZE=64;
  public static final int XCP_ADM_REENCRYPT=25, XCP_SERIALNR_CHARS=8, XCP_ADMCTR_BYTES=16, XCP_ADMFL_DOMAIN=1;
  public static final long XCP_MFL_VIRTUAL=0x10, XCP_MFL_PROBE=0x40, XCP_MFL_MODULE=0x02;

  public interface LibraryApi extends Library {
    LibraryApi INSTANCE=Native.load("ep11",LibraryApi.class);
    int m_init(); long m_add_module(XcpModule m,LongByReference target);
    long m_GetMechanismList(NativeLong slot,Pointer list,LongByReference count,long target);
    long m_GenerateRandom(Pointer out,NativeLong len,long target);
    long m_GenerateKey(CkMechanism m,CkAttribute[] t,NativeLong tc,Pointer pin,NativeLong pinlen,Pointer key,LongByReference keylen,Pointer cs,LongByReference cslen,long target);
    long m_GenerateKeyPair(CkMechanism m,CkAttribute[] pub,NativeLong pubn,CkAttribute[] prv,NativeLong prvn,Pointer pin,NativeLong pinlen,Pointer sk,LongByReference sklen,Pointer pk,LongByReference pklen,long target);
    long m_EncryptSingle(Pointer key,NativeLong keylen,CkMechanism m,Pointer in,NativeLong inlen,Pointer out,LongByReference outlen,long target);
    long m_DecryptSingle(Pointer key,NativeLong keylen,CkMechanism m,Pointer in,NativeLong inlen,Pointer out,LongByReference outlen,long target);
    long m_ReencryptSingle(Pointer k1,NativeLong k1len,Pointer k2,NativeLong k2len,CkMechanism m1,CkMechanism m2,Pointer in,NativeLong inlen,Pointer out,LongByReference outlen,long target);
    long m_SignSingle(Pointer key,NativeLong keylen,CkMechanism m,Pointer in,NativeLong inlen,Pointer out,LongByReference outlen,long target);
    long m_VerifySingle(Pointer key,NativeLong keylen,CkMechanism m,Pointer in,NativeLong inlen,Pointer sig,NativeLong siglen,long target);
    long m_WrapKey(Pointer key,NativeLong keylen,Pointer kek,NativeLong keklen,Pointer mac,NativeLong maclen,CkMechanism m,Pointer out,LongByReference outlen,long target);
    long m_UnwrapKey(Pointer wrapped,NativeLong wrappedlen,Pointer kek,NativeLong keklen,Pointer mac,NativeLong maclen,Pointer pin,NativeLong pinlen,CkMechanism m,CkAttribute[] t,NativeLong tc,Pointer out,LongByReference outlen,Pointer cs,LongByReference cslen,long target);
    long m_DeriveKey(CkMechanism m,CkAttribute[] t,NativeLong tc,Pointer base,NativeLong baselen,Pointer data,NativeLong datalen,Pointer pin,NativeLong pinlen,Pointer out,LongByReference outlen,Pointer cs,LongByReference cslen,long target);
    long xcpa_state(XcpAdmResp block, long target, int flags);
    long xcpa_cmdblock(Pointer block, NativeLong blockLength, int function, XcpAdmResp moduleInfo, Pointer transactionCounter, Pointer payload, NativeLong payloadLength);
    long m_admin(Pointer response, LongByReference responseLength, Pointer response2, LongByReference response2Length, Pointer request, NativeLong requestLength, Pointer signatures, NativeLong signatureLength, long target);
    long xcpa_internal_rv(Pointer response, NativeLong responseLength, XcpAdmResp responseBlock, LongByReference returnValue);
  }
  @Structure.FieldOrder({"host","port"}) public static class XcpModuleSocket extends Structure { public byte[] host=new byte[MAX_FNAME_CHARS+1]; public int port; }
  @Structure.FieldOrder({"lastperf"}) public static class XcpDomainPerf extends Structure { public int[] lastperf=new int[256]; }
  @Structure.FieldOrder({"version","flags","domains","domainmask","socket","moduleNr","mhandle","perf","api"}) public static class XcpModule extends Structure {
    public int version; public long flags; public int domains; public byte[] domainmask=new byte[32]; public XcpModuleSocket socket=new XcpModuleSocket(); public int moduleNr; public Pointer mhandle; public XcpDomainPerf perf=new XcpDomainPerf(); public int api;
  }
  @Structure.FieldOrder({"mechanism","pParameter","ulParameterLen"}) public static class CkMechanism extends Structure {
    public NativeLong mechanism; public Pointer pParameter; public NativeLong ulParameterLen; private Object retained;
    public CkMechanism() {}
    public CkMechanism(long type) {
      this.mechanism = new NativeLong(type);
      this.pParameter = Pointer.NULL;
      this.ulParameterLen = new NativeLong(0);
      write();
    }
    public CkMechanism(long type,byte[] p){ mechanism=new NativeLong(type); if(p==null||p.length==0){pParameter=Pointer.NULL;ulParameterLen=new NativeLong(0);}else{Memory x=mem(p);retained=x;pParameter=x;ulParameterLen=new NativeLong(p.length);} write(); }
    public CkMechanism(long type,Structure p){ mechanism=new NativeLong(type); p.write(); retained=p; pParameter=p.getPointer(); ulParameterLen=new NativeLong(p.size()); write(); }
  }
  @Structure.FieldOrder({"type","pValue","ulValueLen"}) public static class CkAttribute extends Structure { public NativeLong type; public Pointer pValue; public NativeLong ulValueLen; private Memory retained; }
  @Structure.FieldOrder({"fn","domain","domainInst","module","modNr","modInst","tctr","rv","reason","payload","pllen"}) public static class XcpAdmResp extends Structure {
    public int fn, domain, domainInst;
    public byte[] module=new byte[XCP_SERIALNR_CHARS*2];
    public byte[] modNr=new byte[XCP_SERIALNR_CHARS];
    public byte[] modInst=new byte[XCP_SERIALNR_CHARS];
    public byte[] tctr=new byte[XCP_ADMCTR_BYTES];
    public NativeLong rv;
    public int reason;
    public Pointer payload;
    public NativeLong pllen;
  }
  @Structure.FieldOrder({"type","childKeyIndex","pChainCode","ulChainCodeLen","version"}) public static class BtcDeriveParams extends Structure {
    public NativeLong type,childKeyIndex; public Pointer pChainCode; public NativeLong ulChainCodeLen,version; private Memory retained;
    public BtcDeriveParams(long t,long child,byte[] chain,long ver){type=new NativeLong(t);childKeyIndex=new NativeLong(child);version=new NativeLong(ver);if(chain==null||chain.length==0){pChainCode=Pointer.NULL;ulChainCodeLen=new NativeLong(0);}else{retained=mem(chain);pChainCode=retained;ulChainCodeLen=new NativeLong(chain.length);}write();}
  }
  public record Attribute(long type,byte[] value){ public static Attribute bool(long t,boolean v){return new Attribute(t,new byte[]{(byte)(v?1:0)});} public static Attribute ckUlong(long t,long v){Memory m=new Memory(NativeLong.SIZE);m.setNativeLong(0,new NativeLong(v));return new Attribute(t,m.getByteArray(0,NativeLong.SIZE));} public static Attribute bytes(long t,byte[] v){return new Attribute(t,v.clone());} }
  public record KeyResult(byte[] keyBlob,byte[] checksum){} public record KeyPairResult(byte[] publicKey,byte[] privateKey){}
  public static class Ep11Exception extends RuntimeException {public final long rc; Ep11Exception(String op,long rc){super(op+" failed CK_RV=0x"+Long.toUnsignedString(rc,16));this.rc=rc;}}

  public static final class Client {
    private final LibraryApi lib=LibraryApi.INSTANCE; private Memory login; private NativeLong loginLen=new NativeLong(0);
    public long initialize(String text){check(lib.m_init(),"m_init");LongByReference tgt=new LongByReference(XCP_TGT_INIT);String[] pairs=text.trim().split("\\s+");int ok=0;for(String pair:pairs){String[] p=pair.split("\\.");XcpModule m=new XcpModule();m.version=XCP_MOD_VERSION;m.moduleNr=Integer.parseInt(p[0]);setDomain(m.domainmask,Integer.parseInt(p[1]));m.flags=XCP_MFL_PROBE|XCP_MFL_MODULE|(pairs.length>1?XCP_MFL_VIRTUAL:0);m.write();long rc=lib.m_add_module(m,tgt);if(rc==0)ok++;else System.err.printf("m_add_module(%s): 0x%x%n",pair,rc);}if(ok==0)throw new IllegalStateException("No EP11 module initialized");String h=System.getenv("EP11LOGIN");if(h!=null&&!h.isBlank()){byte[] b=HexFormat.of().parseHex(h.trim());login=mem(b);loginLen=new NativeLong(b.length);}return tgt.getValue();}
    public long[] getMechanismList(long t){LongByReference n=new LongByReference();check(lib.m_GetMechanismList(new NativeLong(0),Pointer.NULL,n,t),"GetMechanismList(size)");Memory m=new Memory(Math.max(1,n.getValue()*NativeLong.SIZE));check(lib.m_GetMechanismList(new NativeLong(0),m,n,t),"GetMechanismList");long[] r=new long[Math.toIntExact(n.getValue())];for(int i=0;i<r.length;i++)r[i]=m.getNativeLong((long)i*NativeLong.SIZE).longValue();return r;}
    public byte[] generateRandom(long t,int n){Memory o=new Memory(Math.max(1,n));check(lib.m_GenerateRandom(o,new NativeLong(n),t),"GenerateRandom");return o.getByteArray(0,n);}
    public KeyResult generateKey(long t,CkMechanism m,List<Attribute>a){CkAttribute[] x=attrs(a);Memory o=new Memory(MAX_BLOB_SIZE),c=new Memory(MAX_CSUM_SIZE);LongByReference ol=new LongByReference(MAX_BLOB_SIZE),cl=new LongByReference(MAX_CSUM_SIZE);check(lib.m_GenerateKey(m,x,new NativeLong(x.length),ptr(login),loginLen,o,ol,c,cl,t),"GenerateKey");return new KeyResult(read(o,ol),read(c,cl));}
    public KeyPairResult generateKeyPair(long t,CkMechanism m,List<Attribute>pub,List<Attribute>prv){CkAttribute[] a=attrs(pub),b=attrs(prv);Memory sk=new Memory(MAX_BLOB_SIZE),pk=new Memory(MAX_BLOB_SIZE);LongByReference sl=new LongByReference(MAX_BLOB_SIZE),pl=new LongByReference(MAX_BLOB_SIZE);check(lib.m_GenerateKeyPair(m,a,new NativeLong(a.length),b,new NativeLong(b.length),ptr(login),loginLen,sk,sl,pk,pl,t),"GenerateKeyPair");return new KeyPairResult(read(pk,pl),read(sk,sl));}
    private byte[] crypt(boolean enc,long t,CkMechanism m,byte[] key,byte[] in){Memory k=mem(key),i=mem(in),o=new Memory(MAX_BLOB_SIZE);LongByReference l=new LongByReference(MAX_BLOB_SIZE);long rc=enc?lib.m_EncryptSingle(k,new NativeLong(key.length),m,i,new NativeLong(in.length),o,l,t):lib.m_DecryptSingle(k,new NativeLong(key.length),m,i,new NativeLong(in.length),o,l,t);check(rc,enc?"EncryptSingle":"DecryptSingle");return read(o,l);} public byte[] encryptSingle(long t,CkMechanism m,byte[]k,byte[]i){return crypt(true,t,m,k,i);} public byte[] decryptSingle(long t,CkMechanism m,byte[]k,byte[]i){return crypt(false,t,m,k,i);}
    public byte[] reencryptSingle(long t,CkMechanism m1,CkMechanism m2,byte[]k1,byte[]k2,byte[]in){Memory a=mem(k1),b=mem(k2),i=mem(in),o=new Memory(MAX_BLOB_SIZE);LongByReference l=new LongByReference(MAX_BLOB_SIZE);check(lib.m_ReencryptSingle(a,new NativeLong(k1.length),b,new NativeLong(k2.length),m1,m2,i,new NativeLong(in.length),o,l,t),"ReencryptSingle");return read(o,l);}
    public byte[] signSingle(long t,CkMechanism m,byte[]k,byte[]in){Memory a=mem(k),i=mem(in),o=new Memory(MAX_BLOB_SIZE);LongByReference l=new LongByReference(MAX_BLOB_SIZE);check(lib.m_SignSingle(a,new NativeLong(k.length),m,i,new NativeLong(in.length),o,l,t),"SignSingle");return read(o,l);} public void verifySingle(long t,CkMechanism m,byte[]k,byte[]in,byte[]sig){check(lib.m_VerifySingle(mem(k),new NativeLong(k.length),m,mem(in),new NativeLong(in.length),mem(sig),new NativeLong(sig.length),t),"VerifySingle");}
    public byte[] wrapKey(long t,CkMechanism m,byte[]kek,byte[]key){Memory a=mem(key),b=mem(kek),o=new Memory(MAX_BLOB_SIZE);LongByReference l=new LongByReference(MAX_BLOB_SIZE);check(lib.m_WrapKey(a,new NativeLong(key.length),b,new NativeLong(kek.length),Pointer.NULL,new NativeLong(0),m,o,l,t),"WrapKey");return read(o,l);}
    public KeyResult unwrapKey(long t,CkMechanism m,byte[]kek,byte[]wrapped,List<Attribute>at){CkAttribute[] x=attrs(at);Memory a=mem(wrapped),b=mem(kek),o=new Memory(MAX_BLOB_SIZE),c=new Memory(MAX_CSUM_SIZE);LongByReference l=new LongByReference(MAX_BLOB_SIZE),cl=new LongByReference(MAX_CSUM_SIZE);check(lib.m_UnwrapKey(a,new NativeLong(wrapped.length),b,new NativeLong(kek.length),Pointer.NULL,new NativeLong(0),ptr(login),loginLen,m,x,new NativeLong(x.length),o,l,c,cl,t),"UnwrapKey");return new KeyResult(read(o,l),read(c,cl));}
    public KeyResult deriveKey(long t,CkMechanism m,byte[]base,List<Attribute>at){CkAttribute[] x=attrs(at);Memory b=base==null?null:mem(base),o=new Memory(MAX_BLOB_SIZE),c=new Memory(MAX_CSUM_SIZE);LongByReference l=new LongByReference(MAX_BLOB_SIZE),cl=new LongByReference(MAX_CSUM_SIZE);check(lib.m_DeriveKey(m,x,new NativeLong(x.length),ptr(b),new NativeLong(base==null?0:base.length),Pointer.NULL,new NativeLong(0),ptr(login),loginLen,o,l,c,cl,t),"DeriveKey");return new KeyResult(read(o,l),read(c,cl));}
    public byte[] reencipher(long target, byte[] key) {
      Objects.requireNonNull(key, "key");
      XcpAdmResp state = new XcpAdmResp();
      state.clear(); state.write();
      long stateRc = lib.xcpa_state(state, target, XCP_ADMFL_DOMAIN);
      if (stateRc < 0) throw new IllegalStateException("xcpa_state failed: " + stateRc);
      state.read();

      Memory request = new Memory(MAX_BLOB_SIZE);
      Memory keyMemory = mem(key);
      long requestLength = lib.xcpa_cmdblock(request, new NativeLong(MAX_BLOB_SIZE),
              XCP_ADM_REENCRYPT, state, Pointer.NULL, keyMemory, new NativeLong(key.length));
      if (requestLength < 0) throw new IllegalStateException("xcpa_cmdblock failed: " + requestLength);

      Memory response = new Memory(MAX_BLOB_SIZE);
      LongByReference responseLength = new LongByReference(MAX_BLOB_SIZE);
      LongByReference unusedLength = new LongByReference(0);
      long outerRv = lib.m_admin(response, responseLength, Pointer.NULL, unusedLength,
              request, new NativeLong(requestLength), Pointer.NULL, new NativeLong(0), target);
      check(outerRv, "m_admin(reencipher)");
      if (responseLength.getValue() == 0) throw new IllegalStateException("Empty reencipher response");

      XcpAdmResp result = new XcpAdmResp();
      result.clear(); result.write();
      LongByReference innerRv = new LongByReference(0);
      long parseRc = lib.xcpa_internal_rv(response, new NativeLong(responseLength.getValue()), result, innerRv);
      if (parseRc < 0) throw new IllegalStateException("xcpa_internal_rv failed: " + parseRc);
      if (innerRv.getValue() != CKR_OK) throw new Ep11Exception("reencipher inner response", innerRv.getValue());
      result.read();
      long payloadLength = result.pllen.longValue();
      if (result.payload == null || Pointer.nativeValue(result.payload) == 0)
        throw new IllegalStateException("Reencipher response has no payload");
      if (payloadLength != key.length)
        throw new IllegalStateException("Reencipher changed blob size from " + key.length + " to " + payloadLength);
      return result.payload.getByteArray(0, Math.toIntExact(payloadLength));
    }
  }
  private static CkAttribute[] attrs(List<Attribute>a){CkAttribute[] x=(CkAttribute[])new CkAttribute().toArray(a.size());for(int i=0;i<a.size();i++){x[i].type=new NativeLong(a.get(i).type());x[i].retained=mem(a.get(i).value());x[i].pValue=x[i].retained;x[i].ulValueLen=new NativeLong(a.get(i).value().length);x[i].write();}return x;}
  private static void setDomain(byte[]m,int d){m[d/8]|=(byte)(1<<(7-d%8));} private static Memory mem(byte[]b){Memory m=new Memory(Math.max(1,b.length));if(b.length>0)m.write(0,b,0,b.length);return m;} private static Pointer ptr(Memory m){return m==null?Pointer.NULL:m;} private static byte[] read(Memory m,LongByReference l){return m.getByteArray(0,Math.toIntExact(l.getValue()));} private static void check(long rc,String op){if(rc!=0)throw new Ep11Exception(op,rc);}
}
