import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.util.Random;
import java.util.Scanner;


public class Server {
	private static int SERVER_PORT = 2001;
	
	private static BigInteger p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499");
	private static BigInteger q = new BigInteger("959452661475451209325433595634941112150003865821");
	private static BigInteger g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");

	// CA private key
	private static BigInteger x = new BigInteger("432398415306986194693973996870836079581453988813");
	
	// CA public key
	private static BigInteger y = new BigInteger("49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160");

	private static int pBits = 1024;
	private static int qBits = 160;
	private static int gBits = 1024;
	
	public static void main(String [] args) {
		// Check if CA's key pair is valid
		boolean privateKeyCriteria = x.compareTo(BigInteger.ZERO) == 1 && x.compareTo(q) == -1;
		boolean publicKeyCriteria = g.modPow(x, p).equals(y);
		
		if(privateKeyCriteria && publicKeyCriteria) {

			System.out.println("Wait for the request of a user.....");

			try {
				ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
				Socket client = serverSocket.accept();

				// Get user's identity
				BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
				StringBuilder sb = new StringBuilder();

				String identity = reader.readLine();
				y = new BigInteger(reader.readLine());

				Scanner in = new Scanner(System.in);
				System.out.println("Enter the expiry date of the certificate (yyyy-mm-dd):");
				String expiryDate = in.nextLine();

				while(expiryDate.length() != 10) {
					System.out.println("Date is not valid. Re-enter date (yyyy-mm-dd):");
					expiryDate = in.nextLine();
				}

				BigInteger s = new BigInteger("0");
				BigInteger r = new BigInteger("0");
				BigInteger h = new BigInteger("0");

				while(s.equals(new BigInteger("0"))) {

					// DSS Signature Generation
					Random rnd = new Random();
					BigInteger k = new BigInteger(q.bitLength(), rnd);
					
					r = (g.modPow(k, p)).mod(q);

					final String m = "50";

					MessageDigest messageDigest ;
					try {
						messageDigest = MessageDigest.getInstance("SHA-1");
						messageDigest.update(m.getBytes());
						byte byteData[] = messageDigest.digest();

						h = new BigInteger(byteData);
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					BigInteger i = k.modInverse(q);

					// Solve for s
					s = ((h.add(x.multiply(r))).multiply(i)).mod(q);
				}

				sendMiniCertificate(client, identity, y, expiryDate, r, s, h);
				client.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else {
			System.out.println("Key pairs are not valid.");
		}
	}
	
	/**
	 * Sends mini-certificate to connected client
	 * @param client
	 * @param identity
	 * @param userPublicKey
	 * @param expiryDate
	 * @param r
	 * @param s
	 */
	private static void sendMiniCertificate(Socket client, String identity, BigInteger userPublicKey, 
			String expiryDate, BigInteger r, BigInteger s, BigInteger h) {
		try {
			PrintWriter writer = new PrintWriter(client.getOutputStream(), true);
			writer.println(identity);
			writer.println(userPublicKey.toString());
			writer.println(expiryDate);
			writer.println(r.toString());
			writer.println(s.toString());
			writer.println(h.toString());
			
			System.out.println("The user " + identity + " with IP address " 
					+ client.getRemoteSocketAddress().toString()
					+ " holds the following mini-certificate:");
			
			System.out.println(identity);
			System.out.println(userPublicKey.toString());
			System.out.println(expiryDate);
			System.out.println(r.toString());
			System.out.println(s.toString());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
