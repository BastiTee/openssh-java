import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public final class SSHRSACrypto {

	private SSHRSACrypto() {
	}

	public static PrivateKey readPrivateKey(String body) throws GeneralSecurityException, IOException {
		byte[] bytes = DatatypeConverter.parseBase64Binary(body.replaceAll("[-]+[^-]+[-]+", ""));
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		checkArgument(in.read() == 48, "no id_rsa SEQUENCE");
		checkArgument(in.read() == 130, "no Version marker");
		in.skipBytes(5);
		BigInteger n = readAsnInteger(in);
		readAsnInteger(in);
		BigInteger e = readAsnInteger(in);
		RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, e);
		return KeyFactory.getInstance("RSA").generatePrivate(spec);
	}

	public static PublicKey readPublicKey(String body) throws GeneralSecurityException, IOException {
		byte[] bytes = DatatypeConverter.parseBase64Binary(body.split(" ")[1]);
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		byte[] sshRsa = new byte[in.readInt()];
		in.readFully(sshRsa);
		checkArgument(new String(sshRsa).equals("ssh-rsa"), "no RFC-4716 ssh-rsa");
		byte[] exp = new byte[in.readInt()];
		in.readFully(exp);
		byte[] mod = new byte[in.readInt()];
		in.readFully(mod);
		BigInteger e = new BigInteger(exp);
		BigInteger n = new BigInteger(mod);
		RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
		return KeyFactory.getInstance("RSA").generatePublic(spec);
	}

	public static byte[] encrypt(String text, PublicKey key) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(text.getBytes());
	}

	public static String decrypt(byte[] text, PrivateKey key) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(text));
	}

	private static BigInteger readAsnInteger(DataInputStream in) throws IOException {
		checkArgument(in.read() == 2, "no INTEGER marker");
		int length = in.read();
		if (length >= 0x80) {
			byte[] extended = new byte[4];
			int bytesToRead = length & 0x7f;
			in.readFully(extended, 4 - bytesToRead, bytesToRead);
			length = new BigInteger(extended).intValue();
		}
		byte[] data = new byte[length];
		in.readFully(data);
		return new BigInteger(data);
	}

	private static void checkArgument(boolean expression, Object errorMessage) {
		if (!expression)
			throw new IllegalArgumentException(String.valueOf(errorMessage));
	}

	/**
	 * For testing purposes
	 */
	public static void main(String args[]) throws Exception {

		// read your public and private key file
		String publicKeyBody = new String(Files.readAllBytes(Paths.get("test_rsa.pub")));
		String privateKeyBody = new String(Files.readAllBytes(Paths.get("test_rsa")));

		// Use SSHRSACrypto to read content to java.security objects
		PublicKey publicKey = SSHRSACrypto.readPublicKey(publicKeyBody);
		PrivateKey privateKey = SSHRSACrypto.readPrivateKey(privateKeyBody);

		// Do something useful
		String message = "Hello World.";
		byte[] cipherText = SSHRSACrypto.encrypt(message, publicKey);
		String decrypted = SSHRSACrypto.decrypt(cipherText, privateKey);
		System.err.println("MESSAGE: " + message);
		System.err.println("DECRYPT: " + decrypted);

		// Test if en- and decryption worked
		if (!message.equals(decrypted))
			System.err.println("DECRYPTION FAILED!");
	}
}