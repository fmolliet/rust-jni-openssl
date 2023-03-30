package io.winty.sec;

public class Keyexchange {
    
    private static native void generateKeys(Keys keys);
    
    private static native void exchangeKeys(Keys keys,String privateKey, String publicKey);

    static {
        System.loadLibrary("rustjniopenssl");
    }
    
    public static void main(String[] args) {
        Keys alice = new Keys();
        Keyexchange.generateKeys(alice);
        
        Keys bob = new Keys();
        Keyexchange.generateKeys(bob);
        
        Keyexchange.exchangeKeys(alice, alice.getPrivateKey(), bob.getPublicKey());
        Keyexchange.exchangeKeys(bob, bob.getPrivateKey(), alice.getPublicKey());
        
        System.out.println(alice.toString());
        System.out.println(bob.toString());
    }

}
