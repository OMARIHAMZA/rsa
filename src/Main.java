import rsa.RSA;

public class Main {

    public static void main(String[] args) {
        RSA.RSAKey rsaKey = RSA.generateKey();
        String message = "Hamza Al-Omari";
        System.out.println("Message: " + message);
        String encrypted = RSA.encrypt(message, rsaKey);
        String decrypted = RSA.decrypt(encrypted, rsaKey);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

}
