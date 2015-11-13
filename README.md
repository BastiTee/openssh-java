openssh-java
============

Support for reading OpenSSH RSA keys on the JVM.
This fork adapts Samuel Halliday original code, but has no external dependencies.

Usage
=====

```java
PublicKey publicKey = SSHRSACrypto.readPublicKey(publicKeyBody);
PrivateKey privateKey = SSHRSACrypto.readPrivateKey(privateKeyBody);
```

now you're in the Java Crypto API land and can do this sort of thing:

```java
private byte[] encrypt(String text, PublicKey key) throws GeneralSecurityException {
  Cipher cipher = Cipher.getInstance(RSA);
  cipher.init(Cipher.ENCRYPT_MODE, key);
  return cipher.doFinal(text.getBytes());
}

private String decrypt(byte[] text, PrivateKey key) throws GeneralSecurityException {
  Cipher cipher = Cipher.getInstance(RSA);
  cipher.init(Cipher.DECRYPT_MODE, key);
  return new String(cipher.doFinal(text));
}

...

String message = "Hello World!!1!";
byte[] cipherText = encrypt(message, publicKey);
String decrypted = decrypt(cipherText, privateKey);
```

Installation
============

Just compile the code and play. No dependencies. 

Licence
=======

This code is licensed unter GNU LESSER GENERAL PUBLIC LICENSE.
See LICENSE for details.
