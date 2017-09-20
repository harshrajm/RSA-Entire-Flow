import util.CerUtil;
import util.CsrUtil;
import util.KeyUtil;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

/**
 * Created by Administrator on 18-09-2017.
 */
public class CaMain {

    public static void main(String[] args) {
        CaMain caMain = new CaMain();
        Scanner sc = new Scanner(System.in);

        System.out.println("--CA--");
        System.out.println("1. Generate Keys");
        System.out.println("2. Generate CSR");
        System.out.println("3. Verify Node 1 CSR");
        System.out.println("4. Verify Node 2 CSR");
        System.out.println("5. Generate Node 1 CER");
        System.out.println("6. Generate Node 2 CER");

        int response = sc.nextInt();
        //sc.close();
        switch (response) {
            case 1:
                caMain.generateCaKeys();
                break;
            case 2:
               // Scanner scanner = new Scanner(System.in);
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

                caMain.generateCSR(email, cn, ou, l, o, st, c);
                break;
            case 3:
                boolean b = caMain.verifyNode1CSR();
                if(b){
                    System.out.println("-> Node 1 CSR verified");
                }
                break;
            case 4:
                boolean a = caMain.verifyNode2CSR();
                if(a){
                    System.out.println("-> Node 2 CSR verified");
                }
                break;
            case 5:
                caMain.generateNode1CER();
                break;
            case 6:
                caMain.generateNode2CER();
                break;
            default:
                System.out.println("wrong input!!");

        }
        sc.close();
    }

    private static String readString()
    {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    public void generateCaKeys() {
        new KeyUtil().generateKeys(PathUtil.CA_PUBLIC_KEY, PathUtil.CA_PRIVATE_KEY);
        System.out.println("-> CA Keys Generated");
    }

    public void generateCSR(String email, String cn, String ou, String l, String o, String st, String c) {
        try {
            PrivateKey privateKey = new KeyUtil().getPrivateKey(PathUtil.CA_PRIVATE_KEY);
            PublicKey publicKey = new KeyUtil().getPublicKey(PathUtil.CA_PUBLIC_KEY);
            new CsrUtil().generateCSR(PathUtil.CA_CSR, publicKey, privateKey, email, cn, ou, l, o, st, c);
            System.out.println("-> CA CSR generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean verifyNode1CSR() {
        boolean b = false;

        try {
            b =  new CsrUtil().verifyCSR(PathUtil.NODE_1_CSR);
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
        }
        return b;
    }

    public boolean verifyNode2CSR() {
        boolean b = false;
        try {
            b = new CsrUtil().verifyCSR(PathUtil.NODE_2_CSR);
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
        }
        return b;
    }

    public void generateNode1CER() {

        PublicKey node1PublicKey = null;
        try {
            node1PublicKey = new CsrUtil().getPublicKeyFromCSR(PathUtil.NODE_1_CSR);
        } catch (Exception e) {
            e.printStackTrace();
        }
        PrivateKey caPrivateKey = new KeyUtil().getPrivateKey(PathUtil.CA_PRIVATE_KEY);

        String[] data = new CsrUtil().getDataFromCSR(PathUtil.NODE_1_CSR);
        try {
            new CerUtil().generateCER(PathUtil.NODE_1_CER, node1PublicKey, caPrivateKey, data[0], data[1], data[2], data[3], data[4], data[5], data[6], "CN=www.certifyingauthority.com");
            System.out.println("-> Node 1 CER generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void generateNode2CER() {

        PublicKey node2PublicKey = null;
        try {
            node2PublicKey = new CsrUtil().getPublicKeyFromCSR(PathUtil.NODE_2_CSR);
        } catch (Exception e) {
            e.printStackTrace();
        }
        PrivateKey caPrivateKey = new KeyUtil().getPrivateKey(PathUtil.CA_PRIVATE_KEY);

        String[] data = new CsrUtil().getDataFromCSR(PathUtil.NODE_2_CSR);
        try {
            new CerUtil().generateCER(PathUtil.NODE_2_CER, node2PublicKey, caPrivateKey, data[0], data[1], data[2], data[3], data[4], data[5], data[6], "CN=www.certifyingauthority.com");
            System.out.println("-> Node 2 CER generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
