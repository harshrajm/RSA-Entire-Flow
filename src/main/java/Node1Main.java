import util.CerUtil;
import util.CsrUtil;
import util.EncDcrpt;
import util.KeyUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

/**
 * Created by Administrator on 18-09-2017.
 */
public class Node1Main {

    public static void main(String[] args) {
        Node1Main node1Main = new Node1Main();
        Scanner sc = new Scanner(System.in);

        System.out.println("--Node1--");
        System.out.println("1. Generate Keys");
        System.out.println("2. Generate CSR");
        System.out.println("3. Verify CER of Node2");
        System.out.println("4. Encrypt using CER of Node2");

        int response = sc.nextInt();

        switch (response) {
            case 1:
                node1Main.generateNode1Keys();
                break;
            case 2:
                //Scanner scanner = new Scanner(System.in);
                System.out.println("Enter email:");
                String email = readString();
                System.out.println("Enter common name");
                String cn = readString();
                System.out.println("Enter Organization unit");
                String ou = readString();
                System.out.println("Enter Locality");
                String l = readString();
                System.out.println("Enter Organization");
                String o = readString();
                System.out.println("Enter State");
                String st = readString();
                System.out.println("Enter Country");
                String c = readString();
                //scanner.close();
                node1Main.generateCSRForNode1(email, cn, ou, l, o, st, c);
                break;
            case 3:
                node1Main.verifyNode2CER();
                break;
            case 4:
                //Scanner scan = new Scanner(System.in);
                //System.out.println("Enter data to enc: ");
                //String dataToEnc = sc.next();
                String dataToEnc = getStringfromFile(PathUtil.NODE_1_DATA_TO_ENC);
                //System.out.println("Data Loaded "+dataToEnc);
                String s = new Node1Main().signAndAppend(dataToEnc);
                System.out.println(s);
                node1Main.sendEncDataToNode2(s);

                /*System.out.println("Press 1 to decode the cipher:");
                System.out.println(encData);

                int proceed = sc.nextInt();
                sc.close();
                if (proceed == 1) {
                    Node2Main node2Main = new Node2Main();
                    String decodedStr = node2Main.decodeNode1Cipher(encData);
                    System.out.println("Cipher decoded!, Original Text:");
                    System.out.println(decodedStr);
                }*/
                break;
            default:
                System.out.println("wrong input");
        }
        sc.close();
    }

    private static String readString() {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    public void generateNode1Keys() {
        new KeyUtil().generateKeys(PathUtil.NODE_1_PUBLIC_KEY, PathUtil.NODE_1_PRIVATE_KEY);
        System.out.println("-> Node 1 Keys generated");
    }

    public void generateCSRForNode1(String email, String cn, String ou, String l, String o, String st, String c) {
        try {
            PrivateKey privateKey = new KeyUtil().getPrivateKey(PathUtil.NODE_1_PRIVATE_KEY);
            PublicKey publicKey = new KeyUtil().getPublicKey(PathUtil.NODE_1_PUBLIC_KEY);
            new CsrUtil().generateCSR(PathUtil.NODE_1_CSR, publicKey, privateKey, email, cn, ou, l, o, st, c);
            System.out.println("-> Node1 CSR generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void verifyNode2CER() {
        PublicKey caPublicKey = null;
        try {
            caPublicKey = new CerUtil().getPublicKeyfromCER(PathUtil.CA_CER);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            new CerUtil().verifyCER(PathUtil.NODE_2_CER, caPublicKey);
            System.out.println("-> Node 2 CER verified");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendEncDataToNode2(String dataToEnc) {
        PublicKey node2PublicKey = null;
        try {
            node2PublicKey = new CerUtil().getPublicKeyfromCER(PathUtil.NODE_2_CER);
        } catch (Exception e) {
            e.printStackTrace();
        }
        String encData = null;
        try {
            //System.out.println(node2PublicKey);
            //System.out.println(dataToEnc);
            encData = new EncDcrpt().encrypt(node2PublicKey, dataToEnc);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            KeyUtil.writeToFile(PathUtil.NODE_1_ENC_DATA, encData.getBytes());
            System.out.println("Encrypted data is stored in " + PathUtil.NODE_1_ENC_DATA);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static String getStringfromFile(String filePath) {
        byte[] keyBytes = new byte[0];
        try {
            keyBytes = Files.readAllBytes(new File(filePath).toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(keyBytes);
    }

    public String signAndAppend(String dataToSign) {
        String sig = new EncDcrpt().sign(new KeyUtil().getPrivateKey(PathUtil.NODE_1_PRIVATE_KEY), dataToSign);
        String result = dataToSign + "a1s2dc" + sig;
        return result;
    }

}
