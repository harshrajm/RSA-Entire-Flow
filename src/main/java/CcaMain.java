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
public class CcaMain {

    public static void main(String[] args) {
        CcaMain ccaMain = new CcaMain();
        Scanner sc = new Scanner(System.in);

        System.out.println("--CCA--");
        System.out.println("Choose from below:");
        System.out.println("1. Generate CCA Key Pair");
        System.out.println("2. Verify CA CSR");
        System.out.println("3. Generate CER for CA");
        System.out.println("4. Generate CSR for CCA");
        System.out.println("5. Generate Self signed CER for CCA");
        System.out.println("\n Give your response:");
        int response = sc.nextInt();

        switch (response) {
            case 1:
                ccaMain.generateCcaKeys();
                break;
            case 2:
                ccaMain.verifyCaCSR();
                break;
            case 3:
                ccaMain.generateCaCER();
                break;
            case 4:
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

                ccaMain.generateCcaCSR(email, cn, ou, l, o, st, c);
                break;
            case 5:
                ccaMain.generateCcaCER();
                break;

            default:
                System.out.println("wrong input!");
        }


    }

    private static String readString() {
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    public void generateCcaKeys() {
        new KeyUtil().generateKeys(PathUtil.CCA_PUBLIC_KEY, PathUtil.CCA_PRIVATE_KEY);
        System.out.println("-> CCA keys generated!!");
    }


    public void verifyCaCSR() {
        try {
            new CsrUtil().verifyCSR(PathUtil.CA_CSR);
            System.out.println("-> CA CSR Verified");
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
    }

    public void generateCaCER() {
        PublicKey caPublicKey = null;
        try {
            caPublicKey = new CsrUtil().getPublicKeyFromCSR(PathUtil.CA_CSR);
        } catch (Exception e) {
            e.printStackTrace();
        }
        PrivateKey ccaPrivateKey = new KeyUtil().getPrivateKey(PathUtil.CCA_PRIVATE_KEY);

        String[] data = new CsrUtil().getDataFromCSR(PathUtil.CA_CSR);
        try {
            new CerUtil().generateCER(PathUtil.CA_CER, caPublicKey, ccaPrivateKey, data[0], data[1], data[2], data[3], data[4], data[5], data[6], "CN=www.centralcertifyingauthority.com");
            System.out.println("-> CA CER Generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void generateCcaCSR(String email, String cn, String ou, String l, String o, String st, String c) {
        try {
            PrivateKey privateKey = new KeyUtil().getPrivateKey(PathUtil.CCA_PRIVATE_KEY);
            PublicKey publicKey = new KeyUtil().getPublicKey(PathUtil.CCA_PUBLIC_KEY);
            new CsrUtil().generateCSR(PathUtil.CCA_CSR, publicKey, privateKey, email, cn, ou, l, o, st, c);
            System.out.println("-> CCA CSR generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateCcaCER() {
        PublicKey ccaPublicKey = null;
        try {
            ccaPublicKey = new CsrUtil().getPublicKeyFromCSR(PathUtil.CCA_CSR);
        } catch (Exception e) {
            e.printStackTrace();
        }
        PrivateKey ccaPrivateKey = new KeyUtil().getPrivateKey(PathUtil.CCA_PRIVATE_KEY);

        String[] data = new CsrUtil().getDataFromCSR(PathUtil.CCA_CSR);
        try {
            new CerUtil().generateCER(PathUtil.CCA_CER, ccaPublicKey, ccaPrivateKey, data[0], data[1], data[2], data[3], data[4], data[5], data[6], "CN=www.centralcertifyingauthority.com");
            System.out.println("-> CCA CER Generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
