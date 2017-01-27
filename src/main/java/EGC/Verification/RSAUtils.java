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

public class RSAUtils {
	
	// El metodo getHashCodeMD5 ha sido borrado porque no necesitamos su aplicacion.
	// El metodo getHashCodeSHA ha sido borrado porque no necesitamos su aplicacion.
	// 		ya que este anyo no usamos la encriptacion SHA
	// El metodo returnKeyDES ha sido borrado porque no necesitamos su aplicacion.
	// 		ya que este anyo no usamos la encriptacion DES
	// Los metodos encryptDES y desencryptDES han sido borrado porque no necesitamos su aplicacion.
	// 		ya que este anyo no usamos la encriptacion DES
	
	
	// Metodo que devuelve un par de keys aleatorias(publica y privada) 
	public static KeyPair returnKeysRSA(){
	KeyPairGenerator keyGen = null;
	try {
		keyGen = KeyPairGenerator.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	keyGen.initialize(2048);  // tamano clave 2048 bits
	KeyPair clavesRSA = keyGen.generateKeyPair();
	return clavesRSA;
	}

	
	// Dado un voto(string) y su clave publica encriptamos el voto 
	public static byte[] encryptRSA(PublicKey publicKey,String text){
				
		byte[] res = null;
		try {
			Cipher rsa;
								
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.ENCRYPT_MODE, publicKey);
			    
				
			res = rsa.doFinal(text.getBytes());
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
					
			e.printStackTrace();
		} 		
		return res;
	}
			
	// Dado un voto cifrado(byte[]) y su clave privada desencriptamos el voto
	public static String decryptRSA(PrivateKey privateKey, byte[] cipherText) throws BadPaddingException{
				
		String res = null;
		try {
			Cipher rsa;
								
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, privateKey);
					
			    
			byte[] bytesDesencriptados = rsa.doFinal(cipherText);
			res = new String(bytesDesencriptados);
		} catch (IllegalBlockSizeException  | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
					
			e.printStackTrace();
		}
		return res;
	}

	// No lo usamos actualmente pero puede ser que lo necesitemos en un futuro.
	// Comprueba que las keys pasadas por parametros pertenecen al voto cifrado
	public static boolean checkVoteRSA(byte[] votoCifrado, KeyPair key) {
		
		boolean res = true;
		try {
			PrivateKey privKey = key.getPrivate();
			decryptRSA(privKey, votoCifrado);
		} catch (BadPaddingException e) {
			res = false;
		}
		return res;

	}
}
