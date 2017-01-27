package EGC.Verification;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyManipulator {

	//Genera un string parseable por stringToPrivKey y stringToPubKey
	public static String keyToString(Key key){
		byte[] bytes = key.getEncoded();
		String res = Base64.getEncoder().encodeToString(bytes);
		
		return res;
	}
	
	public static PrivateKey stringToPrivKey(String in) throws NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		byte[] prvBytes = Base64.getDecoder().decode(in);
				
		PrivateKey res = kf.generatePrivate(new PKCS8EncodedKeySpec(prvBytes));
		//fuente: http://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
		
		return res;
	}
	
	public static PublicKey stringToPubKey(String in) throws InvalidKeySpecException, NoSuchAlgorithmException{
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		byte[] pubBytes = Base64.getDecoder().decode(in);
		
		PublicKey res = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
		//fuente: http://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
		
		return res;
	}

}
