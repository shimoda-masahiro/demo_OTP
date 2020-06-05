package com.shimoda.demo.otp;

/**
 * This class provides methods to create a HMAC-based OTP and Time-Based OTP The
 * implementation follow the specifications described on RFC 4226 and RFC6238
 * 
 * For more information about HMAC-based OTP:
 * https://tools.ietf.org/html/rfc4226 For more information about Time-based
 * OTP: https://tools.ietf.org/html/rfc6238
 */

public class OTP {
//	Length of OTP                               0   1   2     3     4       5       6         7         8
	private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

	/**
	 * This method generates a TOTP value using SHA1 algorithm.
	 *
	 * @param key:          the shared secret, HEX encoded
	 * @param time:         a value that reflects a time
	 * @param returnDigits: number of digits to return
	 *
	 * @return: string representing the OTP Code
	 */

	public static String generateTOTP(String key, String time, int returnDigits) {
		return generateTOTP(key, time, returnDigits, HmacHashFunction.SHA1);
	}

	/**
	 * This method generates a TOTP value using SHA256 algorithm.
	 * 
	 * @param key:          the shared secret, HEX encoded
	 * @param time:         a value that reflects a time
	 * @param returnDigits: number of digits to return
	 *
	 * @return: string representing the OTP Code
	 */

	public static String generateTOTP256(String key, String time, int returnDigits) {
		return generateTOTP(key, time, returnDigits, HmacHashFunction.SHA256);
	}

	/**
	 * This method generates a TOTP value using SHA512 algorithm.
	 *
	 * @param key:          the shared secret, HEX encoded
	 * @param time:         a value that reflects a time
	 * @param returnDigits: number of digits to return
	 *
	 * @return: string representing the OTP Code
	 */

	public static String generateTOTP512(String key, String time, int returnDigits) {
		return generateTOTP(key, time, returnDigits, HmacHashFunction.SHA512);
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key:             the shared secret, HEX encoded
	 * @param time:            a value that reflects a time
	 * @param returnDigits:    number of digits to return
	 * @param cryptoAlgorithm: algorithm to calculate the hash
	 *
	 * @return: string representing the OTP Code
	 */

	public static String generateTOTP(String key, String time, int returnDigits, HmacHashFunction cryptoAlgorithm) {
		String result = null;

		// Get the HEX in a Byte[]
		byte[] k = Utils.hexStr2Bytes(key);
		byte[] msg = Utils.hexStr2Bytes(time);
		byte[] hash = Utils.generateHmacHash(cryptoAlgorithm, k, msg);

		// put selected bytes into result int
		int offset = hash[hash.length - 1] & 0xf;

		int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

		int otp = binary % DIGITS_POWER[returnDigits];

		result = Integer.toString(otp);
		while (result.length() < returnDigits)
			result = "0" + result;

		return result;
	}
}