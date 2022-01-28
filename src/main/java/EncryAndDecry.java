import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.Key;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Hex;

public class EncryAndDecry {
	/**
	 * 加密：
	 * 1.设置文件：secret.properties
	 * 2.读取账号文件内容 默认文件.txt
	 * 3.加密内容
	 * 4.输出到新文件 账号密文.txt
	 * 
	 * 解密：
	 * 1.读取密文文件 密文.txt
	 * 2.解密密文 
	 * 3.输出到新文件 默认文件decrypt.txt
	 * 4.解密完成。
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		String absolutePath =System.getProperty("user.dir");
		System.out.println(absolutePath);
		Reader inStream = new InputStreamReader(new FileInputStream(absolutePath+"/src/main/resources/secret.properties"));

		Properties prop = new Properties();
		prop.load(inStream);
		String salt = prop.getProperty("salt");
		String pswd = prop.getProperty("password");
		String path = prop.getProperty("path");
		String secPath = prop.getProperty("path_sec");
		String mingPath = prop.getProperty("path_ming");

		//加密
//		String accountContent = getFileContent(path);
//		String secResult = encrypt(accountContent,salt,pswd);
//		System.out.println("加密后密文:" + secResult);
//		saveToFile(secResult, secPath);

		//解密
//		String secContent = getFileContent(secPath);
//		System.out.println(secContent);
//		String ming_content = decrypt(secContent, salt, pswd);
//		System.out.println("ming_content--->" + ming_content);
//		restoreSecContentToFile(ming_content,mingPath);
	}
	
	private static void restoreSecContentToFile(String content,String path) throws Exception {
		saveToFile(content,path);
		
	}

	public static void saveToFile(String content,String path) throws Exception{
		FileWriter file = new FileWriter(new File(path));
		BufferedWriter writer = new BufferedWriter(file);
		writer.write(content);
		writer.flush();
		writer.close();
	}
	
	public static String encrypt(String sourceContent,String salt,String pswd) throws Exception{
		// 口令与密钥
        PBEKeySpec pbeKeySpec = new PBEKeySpec(pswd.toCharArray()); 
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
        Key key = factory.generateSecret(pbeKeySpec);
        
//		byte[] salt =Hex.decodeHex(saltStr.toCharArray());
		PBEParameterSpec pbeParameterSpac = new PBEParameterSpec(Hex.decodeHex(salt.toCharArray()), 100);
	    Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
	    cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpac);
	    byte[] result = cipher.doFinal(sourceContent.getBytes());
	   
		return Hex.encodeHexString(result);
	}
	public static String decrypt(String secContent,String salt,String pswd) throws Exception{
         // 口令与密钥
        PBEKeySpec pbeKeySpec = new PBEKeySpec(pswd.toCharArray()); 
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
        Key key = factory.generateSecret(pbeKeySpec);
                              
        PBEParameterSpec pbeParameterSpac = new PBEParameterSpec(Hex.decodeHex(salt.toCharArray()), 100);
        Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
        // 解密
        cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpac);
        byte[] result = cipher.doFinal(Hex.decodeHex(secContent.toCharArray()));
		return new String(result);
	}
	
	public static String getFileContent(String path) throws IOException{
		File file = new File(path);
		BufferedReader reader = new BufferedReader(new FileReader(file));
		String result ="";
		String line = "";
		while ((line = reader.readLine())!=null){
			result +=line+"\r\n";
		}
		reader.close();
		return result.trim();
	}
}
