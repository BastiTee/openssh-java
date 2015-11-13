package com.github.bastitee.ssh;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class SSHRSACryptoTest {

	public static final String RSA = "RSA";

	private static byte[] encrypt(String text, PublicKey key) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(text.getBytes());
	}

	private static String decrypt(byte[] text, PrivateKey key) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(text));
	}

	private static String readFile(File file) throws IOException {
		BufferedReader bf = null;
		try {
			StringBuilder body = new StringBuilder();
			InputStream is = new FileInputStream(file);
			bf = new BufferedReader(new InputStreamReader(is, "UTF-8"));
			String line = "";
			while ((line = bf.readLine()) != null) {
				body.append(line).append("\n");
			}
			return body.toString();
		} finally {
			if (bf != null)
				bf.close();
		}
	}

	public static void main(String args[]) throws Exception {
		
		String publicKeyBody = readFile(new File("res/test_rsa.pub"));
		String privateKeyBody = readFile(new File("res/test_rsa"));
				
		PublicKey publicKey = SSHRSACrypto.readPublicKey(publicKeyBody);
		PrivateKey privateKey = SSHRSACrypto.readPrivateKey(privateKeyBody);

		String message = "Hello World.";

		byte[] cipherText = encrypt(message, publicKey);
		String decrypted = decrypt(cipherText, privateKey);

		System.err.println("MESSAGE: " + message);
		System.err.println("DECRYPT: " + decrypted);

		if (!message.equals(decrypted))
			System.err.println("DECRYPTION FAILED!");
	}
}
