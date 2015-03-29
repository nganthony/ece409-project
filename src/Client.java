import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

import com.sun.tools.internal.xjc.reader.xmlschema.bindinfo.BIConversion.Static;


public class Client {

	private static BigInteger p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499");
	private static BigInteger q = new BigInteger("959452661475451209325433595634941112150003865821");
	private static BigInteger g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");

	private static BigInteger x = new BigInteger("432398415306986194693973996870836079581453988813");
	
	// CA public key
	private static BigInteger y = new BigInteger("49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160");
	
	private static int pBits = 1024;
	private static int qBits = 160;
	private static int gBits = 1024;
	
	private static int SERVER_PORT = 2001;
	
	public static void main(String [] args) {
		// Check if p, q, and g satisfy three criteria
		boolean pCriteria = p.isProbablePrime(50) && p.bitLength() >= 512 
				&& p.bitLength() <= 1024 && p.bitLength() % 64 == 0;
		boolean qCriteria = q.bitLength() == 160 && q.isProbablePrime(50) && p.subtract(new BigInteger("1")).mod(q).equals(BigInteger.ZERO);
		boolean gCriteria = g.modPow(q, p).equals(BigInteger.ONE);

		if(pCriteria && qCriteria && gCriteria) {
			Scanner in = new Scanner(System.in);

			System.out.println("Enter the user's identity (max 10 chars):");
			String identity = in.nextLine();

			while(identity.toCharArray().length > 10) {
				System.out.println("User's identity is more than 10 chars. Re-enter:");
				identity = in.nextLine();
			}

			// Pad identity
			StringBuilder identityBuilder = new StringBuilder(identity);
			for(int i = identity.length(); i < 10; i++) {
				identityBuilder.append((char)0);
			}

			System.out.println("Enter the IP address of CA:");
			String ipAddress = in.nextLine();

			// Establish connection to server
			try {
				Socket socketClient = new Socket(ipAddress, SERVER_PORT);

				sendIdentity(socketClient, identityBuilder.toString());

				// Read CA's mini certificate
				BufferedReader reader = new BufferedReader(new InputStreamReader(socketClient.getInputStream()));
				String mcIdentity = reader.readLine();
				y = new BigInteger(reader.readLine());
				String mcExpiryDate = reader.readLine();
				BigInteger r = new BigInteger(reader.readLine());
				BigInteger s = new BigInteger(reader.readLine());	        	        
				BigInteger h = new BigInteger(reader.readLine());

				// DSS Verification
				boolean valid = false;

				// Check if 0 < r < q and 0 < s < q
				if((r.compareTo(new BigInteger("0")) == 1 && r.compareTo(q) == -1) && 
						r.compareTo(new BigInteger("0")) == 1 && s.compareTo(q) == -1) {

					BigInteger u = (h.multiply(s.modInverse(q))).mod(q);
					BigInteger v = (((r.multiply(s.modInverse(q)))).mod(q));
					BigInteger w = g.modPow(u, p).multiply(y.modPow(v, p)).mod(p).mod(q);

					if(w.compareTo(r) == 0) {
						valid = true;
					}
				}

				if(valid) {
					System.out.println("Accept the CA's signature and the mini-certificate is valid!");
					System.out.println("The mini-certificate issued by the CA is:");
					System.out.println(mcIdentity);
					System.out.println(y.toString());
					System.out.println(mcExpiryDate);
					System.out.println(r.toString());
					System.out.println(s.toString());
				}
				else {
					System.out.println("Verification failed");
				}

				socketClient.close();
			} catch (UnknownHostException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		else {
			System.out.println("p, q, and g requirements not satisfied.");
		}
	}
	
	private static void sendIdentity(Socket client, String identity) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(client.getOutputStream(), true);
			writer.println(identity);
			writer.println(y.toString());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
