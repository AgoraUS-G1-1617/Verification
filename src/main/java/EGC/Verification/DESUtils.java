package EGC.Verification;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class DESUtils {
		
		
		
		// Metodo que devuelve un par de keys aleatorias(publica y privada) 		
		public static KeyPair returnKeysDES(){
			
			KeyPairGenerator keyGen = null;
			try {
				keyGen = KeyPairGenerator.getInstance("DES");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			keyGen.initialize(2048);  // tamano clave 2048 bits
			KeyPair clavesDES = keyGen.generateKeyPair();
			return clavesDES;
		}

		
		// Dado un voto(string) y su clave publica encriptamos el voto 
		public static byte[] encryptDES(PublicKey publicKey,String text){
					
			byte[] res = null;
			try {
				Cipher des;
									
				des = Cipher.getInstance("DES/ECB/PKCS1Padding");
				des.init(Cipher.ENCRYPT_MODE, publicKey);
				    
					
				res = des.doFinal(text.getBytes());
			} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
						
				e.printStackTrace();
			} 		
			return res;
		}
		
		
		// Dado un voto cifrado(byte[]) y su clave privada desencriptamos el voto
		public static String decryptDES(PrivateKey privateKey, byte[] cipherText) throws BadPaddingException{
					
			String res = null;
			try {
				Cipher des;
									
				des = Cipher.getInstance("DES/ECB/PKCS1Padding");
				des.init(Cipher.DECRYPT_MODE, privateKey);
						
				    
				byte[] bytesDesencriptados = des.doFinal(cipherText);
				res = new String(bytesDesencriptados);
			} catch (IllegalBlockSizeException  | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
						
				e.printStackTrace();
			}
			return res;
		}
		
}
