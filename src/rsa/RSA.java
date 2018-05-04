package rsa;

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {


    public static RSAKey generateKey() {
        Random random1 = new Random(System.currentTimeMillis());
        Random random2 = new Random(System.currentTimeMillis() * 10);

        int e = (new Random()).nextInt(100); // Public Key

        BigInteger p = BigInteger.probablePrime(32, random1);
        BigInteger q = BigInteger.probablePrime(32, random2);

        BigInteger n = p.multiply(q);

        BigInteger pMinusOne = (p.subtract(new BigInteger("1")));
        BigInteger qMinusOne = (q.subtract(new BigInteger("1")));
        BigInteger phi = pMinusOne.multiply(qMinusOne);

        while (true) {
            BigInteger gcd = phi.gcd(new BigInteger("" + e));
            if (gcd.equals(BigInteger.ONE)) {
                break;
            }
            e++;
        }
        //Private Key d
        BigInteger d = (new BigInteger(e + "")).modInverse(phi);
        RSAKey.PublicKey publicKey = new RSAKey.PublicKey(new BigInteger(e + ""), n);
        RSAKey.PrivateKey privateKey = new RSAKey.PrivateKey(d, n);
        RSAKey rsaKey = new RSAKey(publicKey, privateKey);
        System.out.println(rsaKey);
        return rsaKey;

    }

    public static String encrypt(String message, RSAKey key) {
        if (message == null || key == null) return null;
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < message.length(); i++) {
            BigInteger value = new BigInteger("" + ((int) message.charAt(i)));
            BigInteger cipher = value.modPow(key.getPublicKey().e, key.getPublicKey().n);
            result.append(cipher).append(" ");
        }
        return result.toString();
    }

    public static String decrypt(String message, RSAKey key) {
        if (message == null || key == null) return null;
        StringBuilder result = new StringBuilder();
        Scanner scanner = new Scanner(message).useDelimiter(" ");
        while (scanner.hasNext()) {
            BigInteger plainValue = (new BigInteger(scanner.next())).modPow(key.getPrivateKey().d, key.getPrivateKey().n);
            result.append(((char) plainValue.intValue()));
        }
        return result.toString();
    }

    public static class RSAKey {

        private PublicKey publicKey;
        private PrivateKey privateKey;

        RSAKey(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        private static class PublicKey {
            private BigInteger e, n;

            PublicKey(BigInteger e, BigInteger n) {
                this.e = e;
                this.n = n;
            }
        }

        private static class PrivateKey {
            private BigInteger d, n;

            PrivateKey(BigInteger d, BigInteger n) {
                this.d = d;
                this.n = n;
            }
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        @Override
        public String toString() {
            return ("Public Key: (" + this.publicKey.e + ", " + this.publicKey.n + ")" + "\nPrivate Key: (" + this.privateKey.d + ", " + this.privateKey.n + ")");
        }
    }

}