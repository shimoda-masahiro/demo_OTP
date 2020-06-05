package com.shimoda.demo.otp;

import org.apache.http.client.utils.URIBuilder;

/**
 * This class provides methods to create a URI containing the provided
 * credential for generate QR code can be fed to the Google Authenticator
 * application so that it can configure itself with the data contained therein.
 * 
 * For more information about Google Authenticator:
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */

public final class GoogleAuthenticator {

	private static String HOTP = "hotp";
	private static String TOTP = "totp";

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 *
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param period:      only if type is totp: The period parameter defines a
	 *                     period that a TOTP code will be valid for, in seconds
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	public static String getTOTPURLSHA1(String issuer, String accountName, String secret, String digits,
			String period) {
		return generateOTPURI(TOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, period, null);
	}

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 * 
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param period:      the period parameter defines a period that a TOTP code
	 *                     will be valid for, in seconds
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	public static String getTOTPURLSHA256(String issuer, String accountName, String secret, String digits,
			String period) {
		return generateOTPURI(TOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, period, null);
	}

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 * 
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param period:      the period parameter defines a period that a TOTP code
	 *                     will be valid for, in seconds
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	public static String getTOTPURLSHA512(String issuer, String accountName, String secret, String digits,
			String period) {
		return generateOTPURI(TOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, period, null);
	}

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 *
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param counter:     the counter parameter is required when provisioning a key
	 *                     for use with HOTP. It will set the initial counter value
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	public static String getHOTPURLSHA1(String issuer, String accountName, String secret, String digits,
			String counter) {
		return generateOTPURI(HOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, null, counter);
	}

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 *
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param counter:     the counter parameter is required when provisioning a key
	 *                     for use with HOTP. It will set the initial counter value
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	public static String getHOTPURLSHA256(String issuer, String accountName, String secret, String digits,
			String counter) {
		return generateOTPURI(HOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, null, counter);
	}

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 *
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param counter:     the counter parameter is required when provisioning a key
	 *                     for use with HOTP. It will set the initial counter value
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	public static String getHOTPURLSHA512(String issuer, String accountName, String secret, String digits,
			String counter) {
		return generateOTPURI(HOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, null, counter);
	}

	/**
	 * This method create a URI with the data to necessary to create a QRCode
	 *
	 * @param method:      otp type (HOTP or TOTP)
	 * @param issuer:      a value that identifying the provider or service managing
	 *                     this account
	 * @param accountName: used to identify which account a key is associated with
	 * @param secret:      the shared secret, HEX encoded
	 * @param digits:      number of digits, that represent the length of returned
	 *                     OTP code
	 * @param period:      only if type is totp: The period parameter defines a
	 *                     period that a TOTP code will be valid for, in seconds
	 * @param counter:     only if type is hotp: The counter parameter is required
	 *                     when provisioning a key for use with HOTP. It will set
	 *                     the initial counter value
	 * @param algorithm:   the algorithm used to calculate the hash
	 *
	 * @return: string uri with the data to create a QR Code
	 */

	private static String generateOTPURI(String method, String issuer, String accountName, String secret, String digits,
			HmacHashFunction algorithm, String period, String counter) {

		String secretBase32 = Utils.hexStr2Base32(secret);
		String hashAlgorithm = getAlgorithmName(algorithm);

		StringBuilder path = new StringBuilder();
		path.append("/");
		path.append(issuer);
		path.append(" ");
		path.append(accountName);

		URIBuilder uri = new URIBuilder();
		uri.setScheme("otpauth");
		uri.setHost(method);
		uri.setPath(path.toString());
		uri.setParameter("secret", secretBase32);
		uri.setParameter("algorithm", hashAlgorithm);
		uri.setParameter("digits", digits);

		if (method.equals("hotp"))
			uri.setParameter("counter", counter);

		if (method.equals("totp"))
			uri.setParameter("period", period);

		return uri.toString();
	}

	private static String getAlgorithmName(HmacHashFunction algorithm) {
		switch (algorithm) {
		case SHA1:
			return "SHA1";

		case SHA256:
			return "SHA256";

		case SHA512:
			return "SHA512";

		default:
			throw new IllegalArgumentException(String.format("Unknown algorithm: %s", algorithm));
		}
	}
}
