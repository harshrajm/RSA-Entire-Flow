import util.CerUtil;
import util.CsrUtil;
import util.KeyUtil;

/**
 * Created by Administrator on 18-09-2017.
 */
public class Test {
    public static void main(String[] args){
        KeyUtil keyUtil = new KeyUtil();
        CsrUtil csrUtil = new CsrUtil();
        CerUtil cerUtil = new CerUtil();
        /*new KeyUtil().generateKeys("files/cca/pubKey","files/cca/privKey");
        new KeyUtil().generateKeys("files/ca/pubKey","files/ca/privKey");
        new KeyUtil().generateKeys("files/node1/pubKey","files/node1/privKey");
        new KeyUtil().generateKeys("files/node2/pubKey","files/node2/privKey");*/

        //System.out.println(keyUtil.getPrivateKey("files/node2/privKey"));
        //System.out.println(keyUtil.getPublicKey("files/node2/pubKey"));
        //    public void generateCSR(String filePath, PublicKey publicKey, PrivateKey privateKey,String email,String cn, String ou, String l,String o,String st,String c) throws Exception{
        /*try {
            csrUtil.generateCSR("files/node1/csr",keyUtil.getPublicKey("files/node1/pubKey"),keyUtil.getPrivateKey("files/node1/privKey"),"node1@node1.com","nodeOne.com","test dept","idhar hai","nodeOnePvtLtd","hyd","IN");
        } catch (Exception e) {
            e.printStackTrace();
        }*/
     /*   System.out.println("done!");
    String[] zxc =  csrUtil.getDataFromCSR("files/node1/csr");
    for(String x:zxc){
        System.out.println(x);
    }*/

        /*try {
            System.out.println(csrUtil.getPublicKeyFromCSR("files/node1/csr"));
        } catch (Exception e) {
            e.printStackTrace();
        }*/

        /*try {
            cerUtil.generateCER(PathUtil.NODE_1_CER,keyUtil.getPublicKey(PathUtil.NODE_1_PUBLIC_KEY),keyUtil.getPrivateKey(PathUtil.CA_PRIVATE_KEY),"node1@node1.com","nodeOne.com","test dept","idhar hai","nodeOnePvtLtd","hyd","IN","CN=www.idrbtCA.com");
        } catch (Exception e) {
            e.printStackTrace();
        }*/
        /*try {
            //cerUtil.verifyCER(PathUtil.NODE_1_CER,keyUtil.getPublicKey(PathUtil.CA_PUBLIC_KEY));
            System.out.println(cerUtil.getPublicKeyfromCER(PathUtil.NODE_1_CER));
        } catch (Exception e) {
            e.printStackTrace();
        }*/

       /* try {
            System.out.println(csrUtil.verifyCSR(PathUtil.NODE_1_CSR));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }*/
    }
}
