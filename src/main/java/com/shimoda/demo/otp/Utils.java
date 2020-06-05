package com.shimoda.demo.otp;

import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

public final class Utils {

	/**
	 * This method create a secure random byte array
	 *
	 * @param len: the length of random byte array
	 * 
	 * @return: byte array containing random bytes
	 */

	public static byte[] generateSecretKey(int length) {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[length];
		random.nextBytes(bytes);
		return bytes;
	}

	/**
	 * This method uses the JCE to provide the crypto algorithm. HMAC computes a
	 * Hashed Message Authentication Code with the algorithm hash as a parameter.
	 *
	 * @param algorithm: the algorithm to be use to calculate the hash (HmacSHA1,
	 *                   HmacSHA256, HmacSHA512)
	 * @param keyBytes:  the bytes to use for the HMAC key
	 * @param text:      the message or text to be authenticated
	 * 
	 * @return: byte array containing the calculated hash
	 */

	public static byte[] generateHmacHash(HmacHashFunction algorithm, byte[] keyBytes, byte[] text) {
		try {
			HmacHashFunction alg = algorithm;
			String crypto = alg.getAlgorithm();

			Mac hmac;
			hmac = Mac.getInstance(crypto);
			SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
			hmac.init(macKey);
			return hmac.doFinal(text);
		} catch (GeneralSecurityException gse) {
			throw new UndeclaredThrowableException(gse);
		}
	}

	/**
	 * This method converts a HEX string to Byte[]
	 *
	 * @param hex: the HEX string
	 *
	 * @return: a byte array
	 */

	public static byte[] hexStr2Bytes(String hex) {
		// Adding one byte to get the right conversion
		// Values starting with "0" can be converted
		byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

		// Copy all the REAL bytes, not the "first"
		byte[] bytes = new byte[bArray.length - 1];

		for (int i = 0; i < bytes.length; i++)
			bytes[i] = bArray[i + 1];
		return bytes;
	}

	/**
	 * This method converts a HEX string to Base32
	 *
	 * @param hex: the HEX string
	 *
	 * @return: string converted Base32
	 */

	public static String hexStr2Base32(String hex) {
		byte[] bytes = hexStr2Bytes(hex);

		String base32 = new Base32().encodeToString(bytes);

		return base32;
	}

	/**
	 * This method create a QRCode
	 *
	 * @param qrCodeData: the data in URL encoded
	 * @param filePath:   the path to save the QRCode image (png extension)
	 * @param height:     heigth of the image
	 * @param width:      width of the image
	 *
	 */

	public static void createQRCode(String qrCodeData, String filePath, int height, int width)
			throws WriterException, IOException {
		BitMatrix matrix = new MultiFormatWriter().encode(qrCodeData, BarcodeFormat.QR_CODE, width, height);

		try (FileOutputStream out = new FileOutputStream(filePath)) {
			MatrixToImageWriter.writeToStream(matrix, "png", out);
		}
	}
}
