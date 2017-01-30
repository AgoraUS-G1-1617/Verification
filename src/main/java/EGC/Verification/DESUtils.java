package EGC.Verification;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class DESUtils {
		
		
		
		// Metodo que devuelve un par de keys aleatorias(publica y privada) 		
		public static SecretKey returnKeysDES(){
			
			KeyGenerator generadorDES = null;
			 		try {
			 			generadorDES = KeyGenerator.getInstance("DES");
			 		} catch (NoSuchAlgorithmException e) {
			 			// TODO Auto-generated catch block
			 			e.printStackTrace();
			 		}
			 		generadorDES.init(56); // clave de 56 bits
			 		SecretKey clave = generadorDES.generateKey();
			 		return clave;
		}
		
	
		
		// Dado un voto(string) y su clave publica encriptamos el voto 
		public static byte[] encryptDES(SecretKey Key,String text){
					
			byte[] res = null;
			try {
				Cipher des;
									
				des = Cipher.getInstance("DES/ECB/PKCS5Padding");
				des.init(Cipher.ENCRYPT_MODE, Key);
				    
					
				res = des.doFinal(text.getBytes());
			} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
						
				e.printStackTrace();
			} 		
			return res;
		}
		
		
		// Dado un voto cifrado(byte[]) y su clave privada desencriptamos el voto
		public static String decryptDES(SecretKey privateKey, byte[] cipherText) throws BadPaddingException{
					
			String res = null;
			try {
				Cipher des;
									
				des = Cipher.getInstance("DES/ECB/PKCS5Padding");
				des.init(Cipher.DECRYPT_MODE, privateKey);
						
				    
				byte[] bytesDesencriptados = des.doFinal(cipherText);
				res = new String(bytesDesencriptados);
			} catch (IllegalBlockSizeException  | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
						
				e.printStackTrace();
			}
			return res;
		}
		
}
