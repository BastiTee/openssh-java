package com.github.bastitee.ssh;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.xml.bind.DatatypeConverter;

/**
 * Helper methods for using OpenSSH RSA private ({@code ~/.ssh/id_rsa})
 * and public ({@code ~/.ssh/id_rsa.pub}) keys to perform encryption
 * and decryption of Strings within the J2SE crypto framework.
 */
public final class SSHRSACrypto {

	private static final String RSA = "RSA";

	private SSHRSACrypto() {
		// Utility class so no constructing here
	}

	public static PrivateKey readPrivateKey(String body) throws GeneralSecurityException, IOException {
		byte[] bytes = slurpPrivateKey(body);

		/*
		 Key in the following ASN.1 DER encoding,
		 RSAPrivateKey ::= SEQUENCE {
		   version           Version,
		   modulus           INTEGER,  -- n
		   publicExponent    INTEGER,  -- e
		   privateExponent   INTEGER,  -- d
		   prime1            INTEGER,  -- p
		   prime2            INTEGER,  -- q
		   exponent1         INTEGER,  -- d mod (p-1)
		   exponent2         INTEGER,  -- d mod (q-1)
		   coefficient       INTEGER,  -- (inverse of q) mod p
		   otherPrimeInfos   OtherPrimeInfos OPTIONAL
		 }
		*/
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		try {
			checkArgument(in.read() == 48, "no id_rsa SEQUENCE");
			checkArgument(in.read() == 130, "no Version marker");
			in.skipBytes(5);

			BigInteger n = readAsnInteger(in);
			readAsnInteger(in);
			BigInteger e = readAsnInteger(in);

			RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, e);
			return KeyFactory.getInstance(RSA).generatePrivate(spec);
		} catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	public static PublicKey readPublicKey(String body) throws GeneralSecurityException, IOException {
		byte[] bytes = slurpPublicKey(body);
		// http://stackoverflow.com/questions/12749858
		// http://tools.ietf.org/html/rfc4716
		// http://tools.ietf.org/html/rfc4251
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		try {
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
			return KeyFactory.getInstance(RSA).generatePublic(spec);
		} catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static void checkArgument(boolean expression, Object errorMessage) {
		if (!expression) {
			throw new IllegalArgumentException(String.valueOf(errorMessage));
		}
	}

	// http://msdn.microsoft.com/en-us/library/windows/desktop/bb540806%28v=vs.85%29.aspx
	private static BigInteger readAsnInteger(DataInputStream in) throws IOException {
		checkArgument(in.read() == 2, "no INTEGER marker");
		int length = in.read();
		if (length >= 0x80) {
			byte[] extended = new byte[length & 0x7f];
			in.readFully(extended);
			length = new BigInteger(extended).intValue();
		}
		byte[] data = new byte[length];
		in.readFully(data);
		return new BigInteger(data);
	}

	/**
	 * @param body of {@code ~/.ssh/id_rsa}
	 * @return binary form suitable for use in {@link #readPrivateKey(byte[])}
	 * @throws IOException
	 */
	private static byte[] slurpPrivateKey(String body) throws IOException {
		String ascii = body.replaceAll("[-]+[^-]+[-]+", "");
		return DatatypeConverter.parseBase64Binary(ascii);
	}

	/**
	 * @param body of a single entry {@code ~/.ssh/id_rsa.pub}
	 * @return binary form suitable for use in {@link #readPublicKey(byte[])}
	 * @throws IOException
	 */
	private static byte[] slurpPublicKey(String body) throws IOException {
		String[] contents = body.split(" ");
		checkArgument(contents.length == 3, "not a valid id_rsa.pub");
		return DatatypeConverter.parseBase64Binary(contents[1]);
	}
}