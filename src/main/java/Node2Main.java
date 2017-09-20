import util.CsrUtil;
import util.EncDcrpt;
import util.KeyUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

/**
 * Created by Administrator on 18-09-2017.
 */
public class Node2Main {

    public static void main(String[] args) {
        Node2Main node2Main = new Node2Main();
        Scanner sc = new Scanner(System.in);

        System.out.println("--Node2--");
        System.out.println("1. Generate Keys");
        System.out.println("2. Generate CSR");
        System.out.println("3. Decrypt Message encrypted by Node 1");

        int response = sc.nextInt();

        switch (response) {
            case 1:
                node2Main.generateNode2Keys();
                break;
            case 2:
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
                node2Main.generateCSRForNode2(email, cn, ou, l, o, st, c);
                break;
            case 3:
                String textToDecrypt = Node1Main.getStringfromFile(PathUtil.NODE_1_ENC_DATA);
                String originalTxt = new Node2Main().decodeNode1Cipher(textToDecrypt);
                System.out.println("before splitting : "+originalTxt);
                String[] splitDone =originalTxt.split("a1s2dc");
                System.out.println("After splitting");
                for(String x: splitDone){
                    System.out.println(x);
                }
                System.out.println(new String(splitDone[1].getBytes()));

                try {
                    KeyUtil.writeToFile(PathUtil.NODE_2_DEC_DATA,originalTxt.getBytes());
                    System.out.println("Data Decrypted and written to file "+PathUtil.NODE_2_DEC_DATA);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            default:
                System.out.println("wrong input!");
        }
        sc.close();
    }

    private static String readString() {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    public void generateNode2Keys() {
        new KeyUtil().generateKeys(PathUtil.NODE_2_PUBLIC_KEY, PathUtil.NODE_2_PRIVATE_KEY);
        System.out.println("-> Node 2 Keys Generated");
    }


    public void generateCSRForNode2(String email, String cn, String ou, String l, String o, String st, String c) {
        try {
            PrivateKey privateKey = new KeyUtil().getPrivateKey(PathUtil.NODE_2_PRIVATE_KEY);
            PublicKey publicKey = new KeyUtil().getPublicKey(PathUtil.NODE_2_PUBLIC_KEY);
            new CsrUtil().generateCSR(PathUtil.NODE_2_CSR, publicKey, privateKey, email, cn, ou, l, o, st, c);
            System.out.println("-> Node2 CSR generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String decodeNode1Cipher(String cipherToDecode) {
        PrivateKey node2PrivateKey = new KeyUtil().getPrivateKey(PathUtil.NODE_2_PRIVATE_KEY);
        String decodedTxt = null;
        try {
            decodedTxt = new EncDcrpt().decrypt(node2PrivateKey, cipherToDecode);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return decodedTxt;
    }

}
