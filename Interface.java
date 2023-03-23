import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


public class Interface {
	
	public static String generateCertificate_DSA(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
	    X500Name issuer = new X500Name("CN=Autorité de certification");
	    BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
	    Date notBefore = new Date(System.currentTimeMillis());
	    Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); 
	    X500Name subject = new X500Name("CN=Certificat"); 
	    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKey);
	    ContentSigner signer = new JcaContentSignerBuilder("SHA256WithDSA").build(privateKey);
	    X509CertificateHolder certHolder = certBuilder.build(signer);
	    X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

	    StringWriter stringWriter = new StringWriter();
	    PemWriter pemWriter = new PemWriter(stringWriter);
	    pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
	    pemWriter.flush();
	    pemWriter.close();

	    return stringWriter.toString();
	}

	public static String generateCertificate_RSA(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
	    X500Name issuer = new X500Name("CN=Autorité de certification");
	    BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
	    Date notBefore = new Date(System.currentTimeMillis());
	    Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); 
	    X500Name subject = new X500Name("CN=My Cert"); 
	    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKey);
	    ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
	    X509CertificateHolder certHolder = certBuilder.build(signer);
	    X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

	    StringWriter stringWriter = new StringWriter();
	    PemWriter pemWriter = new PemWriter(stringWriter);
	    pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
	    pemWriter.flush();
	    pemWriter.close();

	    return stringWriter.toString();
	}

	public static String Signature_DSA(String Texte, KeyPair keyPair) throws Exception {

		// Créer une signature DSA
		Signature dsa = Signature.getInstance("SHA256withDSA");
		dsa.initSign(keyPair.getPrivate());
		dsa.update(Texte.getBytes("UTF-8"));
		byte[] signature = dsa.sign();
		

		// Convertir la signature en base64 pour l'affichage
		String encodedSignature = Base64.getEncoder().encodeToString(signature);
		return encodedSignature;
	}
	
	public static String Signature_RSA(String Texte, KeyPair keyPair) throws Exception {

		// Créer une signature DSA
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(keyPair.getPrivate());
		rsa.update(Texte.getBytes("UTF-8"));
		byte[] signature = rsa.sign();

		// Convertir la signature en base64 pour l'affichage
		String encodedSignature = Base64.getEncoder().encodeToString(signature);
		return encodedSignature;
	}
	
	public static boolean verifySignature_DSA(String data, byte[] signature, PublicKey publicKey) throws Exception {
	      // Créer une signature DSA
	      Signature dsa = Signature.getInstance("SHA256withDSA");
	      dsa.initVerify(publicKey);
	      dsa.update(data.getBytes("UTF-8"));

	      // Vérifier la signature
	      boolean verified = dsa.verify(signature);

	      return verified;
	}
	
	public static boolean verifySignature_RSA(String data, byte[] signature, PublicKey publicKey) throws Exception {
	      // Créer une signature DSA
	      Signature dsa = Signature.getInstance("SHA256withRSA");
	      dsa.initVerify(publicKey);
	      dsa.update(data.getBytes("UTF-8"));

	      // Vérifier la signature
	      boolean verified = dsa.verify(signature);

	      return verified;
	}
	public static void main(String[] args) throws Exception {
		
		JFrame Interface = new JFrame();
		Interface.setTitle("Test d'intégrité et d'authentification");
		Interface.setSize(600,483);
		Interface.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JPanel panel1 = new JPanel(), panel2 = new JPanel(), panel3 = new JPanel(), panel4 = new JPanel(), panel5 = new JPanel();
		JPanel panel11 = new JPanel(), panel12 = new JPanel();
		JPanel panel41 = new JPanel(), panel42 = new JPanel();
		JPanel panel31 = new JPanel(), panel32 = new JPanel();
		JPanel panel51 = new JPanel(), panel52 = new JPanel();
		
		 final JLabel resultat = new JLabel("Texte indisponible");
		
		final JTextArea Certificat_Text = new JTextArea(7,33);
		
		Certificat_Text.setLineWrap(true);
		Certificat_Text.setWrapStyleWord(true);

		JScrollPane scrollPane = new JScrollPane(Certificat_Text);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		
		JButton signer = new JButton("Signer"), verifier = new JButton("Vérifier");
		JButton reset1 = new JButton("Reset"), reset2 = new JButton("Reset");
		JButton certificat = new JButton("Afficher le certificat");
		
		
		 final JTextField Texte = new JTextField(250);
		 final JTextField SignatureTexte = new JTextField(600);
		
		String[] signatures = {"DSA","RSA"};
		 final JComboBox<String> signature = new JComboBox<>(signatures);
		
		panel1.setPreferredSize(new Dimension(200,100));
		panel1.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.BLACK,2),"Texte à signer"));
		
		panel2.setPreferredSize(new Dimension(200,200));
		panel4.setPreferredSize(new Dimension(200,130));
		panel5.setPreferredSize(new Dimension(200,65));
		panel4.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.BLACK,2),"Signature "));
		panel5.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.BLACK,2),"Vérification"));
		panel11.setPreferredSize(new Dimension(387,100));
		
		panel41.setPreferredSize(new Dimension(387,100));
		panel42.setPreferredSize(new Dimension(90,100));
		
		panel3.setPreferredSize(new Dimension(200,150));
		panel3.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.BLACK,2),"Certificat"));
		panel32.setPreferredSize(new Dimension(200,100));
		
		panel1.setLayout(new BorderLayout());
		panel1.add(panel11, BorderLayout.WEST);
		panel1.add(panel12, BorderLayout.EAST);
		panel42.add(signature);
		panel42.add(signer);
		panel42.add(reset1);
		panel11.setLayout(new BorderLayout());
		panel11.add(Texte,BorderLayout.CENTER);
		panel12.add(reset1);
		panel41.setLayout(new BorderLayout());
		panel41.add(SignatureTexte, BorderLayout.CENTER);
		panel42.add(reset2);
		panel2.setLayout(new BorderLayout());
		panel4.setLayout(new BorderLayout());
		panel5.setLayout(new BorderLayout());
		
		panel4.add(panel41, BorderLayout.WEST);
		panel4.add(panel42, BorderLayout.EAST);
		panel2.add(panel4, BorderLayout.NORTH);
		panel2.add(panel5, BorderLayout.SOUTH);
		panel5.add(panel51, BorderLayout.WEST);
		panel5.add(panel52, BorderLayout.EAST);
		panel52.add(verifier);
		panel51.add(resultat);
		panel3.setLayout(new BorderLayout());
		panel32.add(certificat);
		panel31.add(scrollPane);
		panel3.add(panel31, BorderLayout.CENTER);
		panel3.add(panel32, BorderLayout.EAST);
		Interface.setLayout(new BorderLayout());
		Interface.add(panel1,BorderLayout.NORTH);
		Interface.add(panel2,BorderLayout.CENTER);
		Interface.add(panel3,BorderLayout.SOUTH);
		
		reset1.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt) {
				Texte.setText("");
			}
		});
		
		reset2.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt) {
				SignatureTexte.setText("");
			}
		});
		
		//DSA
		KeyPairGenerator keyGen_DSA = KeyPairGenerator.getInstance("DSA");
	    SecureRandom random1 = SecureRandom.getInstanceStrong();
	    keyGen_DSA.initialize(1024, random1);
	     final KeyPair keyPair_DSA = keyGen_DSA.generateKeyPair();
	    
	    //RSA
	    KeyPairGenerator keyGen_RSA = KeyPairGenerator.getInstance("RSA");
	    SecureRandom random2 = SecureRandom.getInstanceStrong();
	    keyGen_RSA.initialize(1024, random2);
	     final KeyPair keyPair_RSA = keyGen_RSA.generateKeyPair();
	     
	     certificat.addActionListener(new ActionListener(){
				public void actionPerformed(ActionEvent evt) {
					String Certificat;
					if (signature.getSelectedItem().toString().equalsIgnoreCase("DSA")) {
						try {
							Certificat = generateCertificate_DSA(keyPair_DSA.getPrivate(),keyPair_DSA.getPublic());
							Certificat_Text.setText(Certificat);
						}
						catch(Exception e){
							
						}
					}
					else {
						try {
							Certificat = generateCertificate_RSA(keyPair_RSA.getPrivate(),keyPair_RSA.getPublic());
							Certificat_Text.setText(Certificat);
						}
						catch(Exception e){
							
						}
					}
				}
			});
		
		signer.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt) {
				String texte = Texte.getText();
				if (signature.getSelectedItem().toString().equalsIgnoreCase("DSA")) {
					try {
						String Signature_texte = Signature_DSA(texte, keyPair_DSA);
						SignatureTexte.setText(Signature_texte);
					}
					catch(Exception e){
						
					}
				}
				else {
					try {
						String Signature_texte = Signature_RSA(texte, keyPair_RSA);
						SignatureTexte.setText(Signature_texte);
					}
					catch(Exception e){
						
					}
				}
			}
		});
		
		verifier.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt) {
				String texte = Texte.getText();
				String Sign = SignatureTexte.getText();
				if (signature.getSelectedItem().toString().equalsIgnoreCase("DSA")) {
					try {
						if (verifySignature_DSA(texte, Base64.getDecoder().decode(Sign), keyPair_DSA.getPublic())) {
							resultat.setText("Vérification réussie de la signature");
						}
						else{
							resultat.setText("La signature n'est pas vérifiée");
						}
					}
					catch(Exception e){
						resultat.setText("Texte indisponible");
					}
				}
				else {
					try {
						if (verifySignature_RSA(texte, Base64.getDecoder().decode(Sign), keyPair_RSA.getPublic())) {
							resultat.setText("Vérification réussie de la signature");
						}
						else{
							resultat.setText("La signature n'est pas vérifiée");
						}
					}
					catch(Exception e){
						resultat.setText("Texte indisponible");
					}
				}
			}
		});
		
        Interface.setLocationRelativeTo(null);
        Interface.setVisible(true);
	}

}
