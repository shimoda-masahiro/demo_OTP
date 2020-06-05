package com.shimoda.demo.otp;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.TimeZone;
import org.apache.commons.codec.binary.Hex;

import com.google.zxing.WriterException;

public class App {
	public static void main(String[] args) throws WriterException, IOException {
		try {
			/**
			 * Use the code above to create Seeds 160, 256 and 512 bits
			 **/

			// Seed for HMAC-SHA1 - 20 bytes
//			byte[] seed20 = Utils.generateSecretKey(20);
//			String seed20HexKey = Hex.encodeHexString(seed20);

			// Seed for HMAC-SHA256 - 32 bytes
//			byte[] seed32 = Utils.generateSecretKey(32);
//			String seed32HexKey = Hex.encodeHexString(seed32);

			// Seed for HMAC-SHA512 - 64 bytes
//			byte[] seed64 = Utils.generateSecretKey(64);
//			String seed64HexKey = Hex.encodeHexString(seed64);

			String seed20HexKey = "ef5b6f834c69937ee5439778271957064fb18612";
			String seed32HexKey = "6f4d854629adc4754b8510dcdd1aac34fe5e6b1bea10f51359eda25125df28b6";
			String seed64HexKey = "cdf1ab398c39ecd0c27a8e954d7d7179af14343da14dc6ef7cbabac6becaf1a4bb89eb34bbbc78bfb84ee835511994e1fd6ef1f407c064f16f6709b3dee2b0b1";

			long period = 30;
			int returnDigits = 6;

			long sync = 0;

			long unixTimestamp = Instant.now().getEpochSecond();

			long time = (unixTimestamp - sync) / period;
			String counter = Long.toHexString(time).toUpperCase();

			while (counter.length() < 16)
				counter = "0" + counter;

			String otpSHA1 = OTP.generateTOTP(seed20HexKey, counter, returnDigits, HmacHashFunction.SHA1);
			String otpSHA256 = OTP.generateTOTP(seed32HexKey, counter, returnDigits, HmacHashFunction.SHA256);
			String otpSHA512 = OTP.generateTOTP(seed64HexKey, counter, returnDigits, HmacHashFunction.SHA512);

			DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			df.setTimeZone(TimeZone.getTimeZone("UTC"));
			String fmtTime = String.format("%1$-11s", unixTimestamp);
			String utcTime = df.format(new Date(unixTimestamp * 1000));

			System.out
					.println("+---------------+-----------------------+" + "------------------+--------+-----------+");
			System.out
					.println("|  Time(sec)    |   Time (UTC format)   " + "| Value of T(Hex)  |  TOTP  | Algorithm |");
			System.out
					.println("+---------------+-----------------------+" + "------------------+--------+-----------+");
			System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + counter + " | ");
			System.out.println(otpSHA1 + " | SHA1      |");
			System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + counter + " | ");
			System.out.println(otpSHA256 + " | SHA256    |");
			System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + counter + " | ");
			System.out.println(otpSHA512 + " | SHA512    |");

			System.out
					.println("+---------------+-----------------------+" + "------------------+--------+-----------+");

			/**
			 * Use the code above to create QRCode with OTP data to use in Google
			 * Authenticator
			 **/

//			String accountName = "(otp.demo@shimoda.com)";
//			String issuerSHA1 = "Demo SHA1";
//			String issuerSHA256 = "SHA256";
//			String issuerSHA512 = "SHA512";
//
//			String qrCodeDataSHA1 = GoogleAuthenticator.getTOTPURLSHA1(issuerSHA1, accountName, seed20HexKey,
//					String.valueOf(returnDigits), String.valueOf(period));
//			String qrCodeDataSHA256 = GoogleAuthenticator.getTOTPURLSHA256(issuerSHA256, accountName, seed32HexKey,
//					String.valueOf(returnDigits), String.valueOf(period));
//			String qrCodeDataSHA512 = GoogleAuthenticator.getTOTPURLSHA512(issuerSHA512, accountName, seed64HexKey,
//					String.valueOf(returnDigits), String.valueOf(period));
//
//			Utils.createQRCode(qrCodeDataSHA1, "/Users/user/Downloads/QRCode/GoogleAuthenticator_QRCode_SHA12.png", 340,
//					340);
//			Utils.createQRCode(qrCodeDataSHA256,
//					"/Downloads/QRCode/GoogleAuthenticator_QRCode_SHA256.png", 340, 340);
//			Utils.createQRCode(qrCodeDataSHA512,
//					"/Downloads/QRCode/GoogleAuthenticator_QRCode_SHA512.png", 340, 340);
		} catch (final Exception e) {
			System.out.println("Error : " + e);
		}
	}
}