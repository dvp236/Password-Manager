import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


public class Encrypt {
     
	public static void main(String[] args){
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
			Key skeySpec = KeyGenerator.getInstance("AES").generateKey();
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			
			System.out.println(Arrays.toString(cipher.doFinal(new byte[] { 0, 1, 2, 3 })));
			
			System.out.println(encryptECB("dharmik"));
			System.out.println(decryptECB(encryptECB("dharmik")));
			
			System.out.println(encryptCBC("dharmik"));
			System.out.println(decryptCBC(encryptCBC("dharmik")));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	 private static byte[] key = {
         0x74, 0x68, 0x69, 0x73, 0x49, 0x73, 0x41, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79
 };//"thisIsASecretKey";

 public static String encryptECB(String strToEncrypt)
 {
     try
     {
         Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
         final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
         cipher.init(Cipher.ENCRYPT_MODE, secretKey);
         final byte[] encryptedString = Base64.encodeBase64(cipher.doFinal(strToEncrypt.getBytes()));
         return new String(encryptedString);
     }
     catch (Exception e)
     {
        e.printStackTrace();
     }
     return null;

 }
 public static String decryptECB(String strToEncrypt)
 {
     try
     {
         Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
         final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
         cipher.init(Cipher.DECRYPT_MODE, secretKey);
         byte[] dval=new Base64().decode(strToEncrypt.getBytes());
         final byte[] decryptedString = cipher.doFinal(dval);
         return new String(decryptedString);
     }
     catch (Exception e)
     {
        e.printStackTrace();
     }
     return null;

 }
 private static byte[] encryptCBC(String strToEncrypt) throws InvalidKeyException,
 InvalidAlgorithmParameterException, IllegalBlockSizeException,
 BadPaddingException, UnsupportedEncodingException {
	 Cipher c;
	try {
		c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		 final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		 byte[] byteToEncrypt = strToEncrypt.getBytes("UTF-8");
	c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(key));
	byte[] encryptedBytes = c.doFinal(byteToEncrypt);
	return encryptedBytes;
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	return null;

}


private static String decryptCBC(byte[] byteToDecrypt) throws InvalidKeyException,
 InvalidAlgorithmParameterException, IllegalBlockSizeException,
 BadPaddingException {
	Cipher c;
	try {
		c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		c.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(key));

		byte[] plainByte = c.doFinal(byteToDecrypt);

		String plainText = new String(plainByte);
		return plainText;
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	return null;



}

}
