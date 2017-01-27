package EGC.Verification;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;

//para exportar .jar ejecutable:
//-clic derecho en el proyecto en eclipse
//-Exportar
//-en el selector de export wizard, Java>JAR file
//-Select the export destination: <camino>/verification.jar
//-dando Next hasta la ultima pagina: Select the class of the application entry point:Browse y se marca esta clase.
//-Finish.

//para generar con maven:
//mvn clean compile package assembly:assembly
public class EntryPoint {
	
	public static void main(String[] args) {
		try{
			switch(args[0]){
			case "cipher":
				PublicKey pubKey = KeyManipulator.stringToPubKey(args[2]);
				String cifrado = Base64.getEncoder().encodeToString(RSAUtils.encryptRSA(pubKey, args[1]));
				System.out.println(cifrado);
				break;
			case "decipher":
				byte[] bytesCifrados = Base64.getDecoder().decode(args[1]);
				PrivateKey privKey = KeyManipulator.stringToPrivKey(args[2]);
				String descifrado = RSAUtils.decryptRSA(privKey, bytesCifrados);
				System.out.println(descifrado);
				break;
			case "keys":
				KeyPair keys = RSAUtils.returnKeysRSA();
				System.out.println(KeyManipulator.keyToString(keys.getPublic()));
				System.out.println(KeyManipulator.keyToString(keys.getPrivate()));
				break;
			default:
			case "help":
				showHelp();
				break;
			}
		}
		catch(InvalidKeySpecException | NoSuchAlgorithmException | BadPaddingException e){
			System.out.println("Error:");
			e.printStackTrace();
			
			showHelp();
		}
		catch(ArrayIndexOutOfBoundsException e){			
			showHelp();
		}
	}
	
	//muestra el manual de uso en caso de invocacion de help 
	private static void showHelp(){
		System.out.println("Uso:");
		System.out.println("java -jar verification.jar <comando> [parametros]");
		System.out.println("Comandos:");
		System.out.println("help                         Muestra esta pagina de ayuda.");
		System.out.println("cipher <dato> <clave>        Cifra <dato> usando la clave publica RSA <clave>.");
		System.out.println("decipher <cifrado> <clave>   Descifra <cifrado> usando la clave privada RSA <clave>.");
		System.out.println("keys                         Genera un par de claves RSA.\n");
		System.out.println("->Las claves y textos cifrados se entregan como representación textual en Base64.");
		System.out.println("->El comando keys devuelve primero la clave publica y despues la privada, ambas con el mismo formato y separadas por un salto de linea.");
	}
	
}
