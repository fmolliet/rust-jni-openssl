package io.winty.sec;

public class Keys {
    private String privateKey;
    private String publicKey;
    private String secret;

    public String getPrivateKey() {
        return privateKey;
    }
    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
    public String getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
    public String getSecret() {
        return secret;
    }
    public void setSecret(String secret) {
        this.secret = secret;
    }
    
    public void onKeysGenerated(String private_key, String public_key){
        this.privateKey = private_key;
        this.publicKey = public_key;
    }
    
    public void onKeyExchange(String secret){
        this.secret = secret;
    }
    
    @Override
    public String toString() {
        return "Keys [privateKey=" + privateKey + ", publicKey=" + publicKey + ", secret=" + secret + "]";
    }
    
}