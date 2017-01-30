package EGC.Verification;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class VerificationTest {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	//actualizados en el trabajo de 2016/17
	
	// Los tests testGetKeyDes(), testEncryptDES(), testDecryptDES(), testGetMD5(), testGetSHA1()
	// 		han sido borrados ya que los metodos han sido borrados en RSAUtils
	
	@Test
	public void testPubKeyStringConversion() throws InvalidKeySpecException, NoSuchAlgorithmException{
		System.out.println("==========================================================");
		System.out.println("==============TEST 1 (KEY TO STRING PUBLIC)=============");
		System.out.println("==========================================================");
		System.out.println("");
		KeyPair keys = RSAUtils.returnKeysRSA();
		PublicKey k = keys.getPublic();
		
		String s = KeyManipulator.keyToString(k);
		PublicKey k2 = KeyManipulator.stringToPubKey(s);
		
		assertEquals(k, k2);
		System.out.println("Key publica: "+ KeyManipulator.keyToString(k));
		System.out.println("Key publica pasada a string: " + s);
		System.out.println("");
	}
	
	@Test
	public void testPrivKeyStringConversion() throws NoSuchAlgorithmException, InvalidKeySpecException{
		System.out.println("==========================================================");
		System.out.println("==============TEST 2 (KEY TO STRING PRIVATE)=============");
		System.out.println("==========================================================");
		System.out.println("");
		
		KeyPair keys = RSAUtils.returnKeysRSA();
		PrivateKey k = keys.getPrivate();
		
		String s = KeyManipulator.keyToString(k);
		PrivateKey k2 = KeyManipulator.stringToPrivKey(s);
		assertEquals(k, k2);
		System.out.println("Key publica: "+ KeyManipulator.keyToString(k));
		System.out.println("Key privada pasada a string: " + s);
		System.out.println("");
	}
	
	@Test
	public void testGetKeysRsa() {
		System.out.println("==========================================================");
		System.out.println("=================TEST 3 (GENERAR KEYS RSA)================");
		System.out.println("==========================================================");
		System.out.println("");
		
		KeyPair keys = RSAUtils.returnKeysRSA();
		System.out.println("----------------------------KEYS--------------------------");
		System.out.println("-------------Son las keys que hemos generado--------------");
		System.out.println("Key privada: " + KeyManipulator.keyToString(keys.getPrivate()));
		System.out.println("Key publica: " + KeyManipulator.keyToString(keys.getPublic()));
		assertNotNull(keys.getPrivate());
		assertNotNull(keys.getPublic());
		System.out.println("");
	}
	
	@Test
	public void testDecryptRSA() throws NoSuchAlgorithmException, IOException, BadPaddingException {
		System.out.println("==========================================================");
		System.out.println("=================TEST 4 (DESENCRIPTAR RSA)================");
		System.out.println("==========================================================");
		System.out.println("");
		
		KeyPair keys = RSAUtils.returnKeysRSA();
		PublicKey pubKey = keys.getPublic();
		PrivateKey privKey = keys.getPrivate();
		String entrada="Esto es una prueba";
		byte[] res = RSAUtils.encryptRSA(pubKey, entrada);
		System.out.println("----------------------------KEYS--------------------------");
		System.out.println("----Son las keys con las que hemos encriptado el voto-----");
		System.out.println("Key privada: " + KeyManipulator.keyToString(keys.getPrivate()));
		System.out.println("Key publica: " + KeyManipulator.keyToString(keys.getPublic()));
		System.out.println("----------------------Resultados--------------------------");
		System.out.println("Voto entrada: " + entrada);
		System.out.println("Encriptamos...");
		System.out.println("Voto encriptado :" + Arrays.toString(res));
		System.out.println("Desencriptamos...");
		String salida = RSAUtils.decryptRSA(privKey, res);
		assertNotNull(salida);
		System.out.println("Voto desencriptado: " + salida);
		assertEquals(entrada, salida);
		System.out.println("");	
	}
	
	@Test
	public void testCheckVoteRSA() throws NoSuchAlgorithmException, IOException {
		System.out.println("==========================================================");
		System.out.println("===============TEST 5 (COMPROBAR VOTES RSA)===============");
		System.out.println("==========================================================");
		System.out.println("");
		
		KeyPair keys = RSAUtils.returnKeysRSA();
		KeyPair keysAuxiliar = RSAUtils.returnKeysRSA();
		PublicKey pubKey = keys.getPublic();
		byte[] votoCifrado = RSAUtils.encryptRSA(pubKey, "Esto es una prueba");
		boolean comprobacion = RSAUtils.checkVoteRSA(votoCifrado, keys);
		boolean comprobacionAuxiliar = RSAUtils.checkVoteRSA(votoCifrado, keysAuxiliar);
		System.out.println("---------------------------KEYS---------------------------");
		System.out.println("------Son las keys con las que hemos creado el voto-------");
		System.out.println("Key privada: " + KeyManipulator.keyToString(keys.getPrivate()));
		System.out.println("Key publica: " + KeyManipulator.keyToString(keys.getPublic()));
		System.out.println("");
		System.out.println("--Keys creadas para la comprobacion erronea del checkKey--");
		System.out.println("Key privada: " + KeyManipulator.keyToString(keysAuxiliar.getPrivate()));
		System.out.println("Key publica: " + KeyManipulator.keyToString(keysAuxiliar.getPublic()));
		System.out.println("----------------------Resultados--------------------------");
		System.out.println("Comprobacion con las keys correctas");
		if(comprobacion)
			System.out.println("Votacion correcta");
		else 
			System.out.println("Votacion amanyada");
		System.out.println("Comprobacion con las keys incorrectas");
		if(comprobacionAuxiliar)
			System.out.println("Votacion correcta");
		else 
			System.out.println("Votacion amanyada");
		System.out.println("");
	}

	@Test
	public void testEncryptRSA() throws NoSuchAlgorithmException, IOException {

		System.out.println("==========================================================");
		System.out.println("==================TEST 6 (ENCRIPTAR RSA)==================");
		System.out.println("==========================================================");
		System.out.println("");
		
		KeyPair keys = RSAUtils.returnKeysRSA();
		PublicKey pubKey = keys.getPublic();
		byte[] res = RSAUtils.encryptRSA(pubKey, "Esto es una prueba");
		assertNotNull(res);
		System.out.println("----------------------------KEYS--------------------------");
		System.out.println("--Son las keys con las que hemos encriptado el voto--");
		System.out.println("Key privada: " + KeyManipulator.keyToString(keys.getPrivate()));
		System.out.println("Key publica: " + KeyManipulator.keyToString(keys.getPublic()));
		System.out.println("----------------------Resultados--------------------------");
		System.out.println("Voto encriptado: " + Arrays.toString(res));
		System.out.println("");
	}
	
	
	
	
	
	/////////////////////////////////////
	
	@Test
	public void testGetKeyDes() {
		System.out.println("==========================================================");
		System.out.println("==================TEST 7 (GENERAR KEY DES)================");
		System.out.println("==========================================================");
		System.out.println("");
		SecretKey key = DESUtils.returnKeysDES();
		System.out.println("----------------------------KEY---------------------------");
		System.out.println("------------------Key privada generada--------------------");
		System.out.println("Key privada: " + KeyManipulator.keyToString(key));
		assertNotNull(key);
		System.out.println(" ");
	}


	@Test
	public void testEncryptDES() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		System.out.println("==========================================================");
		System.out.println("==================TEST 8 (ENCRIPTAR DES)==================");
		System.out.println("==========================================================");
		System.out.println("");
		SecretKey key = DESUtils.returnKeysDES();
		System.out.println("------------------Key privada generada--------------------");
		System.out.println("Key privada: " + KeyManipulator.keyToString(key));

		System.out.println("------------------------Resultado-------------------------");
		String entrada = "Esto es una prueba";
		System.out.println("Voto entrada: " + entrada);
		System.out.println("Encriptamos..");
		byte[] enc = DESUtils.encryptDES(key, entrada);

		System.out.println("Voto encriptado: " + Arrays.toString(enc));
		System.out.println(" ");
	}

	@Test
	public void testDecryptDES() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		System.out.println("==========================================================");
		System.out.println("==================TEST 9 (DESENCRIPTAR DES)===============");
		System.out.println("==========================================================");
		System.out.println("");
		SecretKey key = DESUtils.returnKeysDES();
		System.out.println("------------------Key privada generada--------------------");
		System.out.println("Key privada: " + KeyManipulator.keyToString(key));
		System.out.println("------------------------Resultado-------------------------");
		String entrada = "Esto es una prueba";
		System.out.println("Voto entrada: " + entrada);
		System.out.println("Encriptamos..");
		byte[] enc = DESUtils.encryptDES(key, entrada);
		System.out.println("Voto encriptado: " + Arrays.toString(enc));
		System.out.println("Desencriptamos..");
		String fin = DESUtils.decryptDES(key, enc);
		assertNotNull(fin);
		System.out.println("Voto Desencriptado en DES: " + new String(enc) + " -> " + fin);
	}
	

}
