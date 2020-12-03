package rsa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Scanner;

public class rsa_client {
	
	Socket socket;
	BufferedReader reader;
	PrintWriter writer;
	Scanner sc;
	
	public rsa_client() {
		try {
			//accept()호출되고, 쓰레드 만들어지고, 백터에 추가됨.
			socket = new Socket("localhost", 20000);
			SocketThread st = new SocketThread();
			st.start();
			
			writer = new PrintWriter(socket.getOutputStream(), true);
			sc = new Scanner(System.in);
			
			int p = 7; //소수 p
			int q = 5; //소수 q
			int N = p * q; 
			int L = (p - 1) * (q - 1);
			int E = 5; //5로 설정
			
			//암호화 과정
			int pm = 3; //평문
			int c_pm = 0;
			int pm2 = 3;
			for(int i = 0; i < E - 1; i++) {
				pm2 = pm2 * pm;  //평문의 E 제곱을 구한다.
			}	
			c_pm = pm2 % N; //암호문 = (평문의 E 제곱) mod N이다.
			
			System.out.println("- 암호화 과정 -");
			System.out.println("소수 p: " + p);
			System.out.println("소수 q: " + q);
			System.out.println("N: " + N);
			System.out.println("L: " + L);
			System.out.println("E: " + E);
			System.out.println("평문: " + pm);
			System.out.println("생성된 암호문: " + c_pm);
			
			//일방향 해시 함수 생성
			System.out.println("\n- 일방향 해시 함수 -");
			SHA_256 sha_256 = new SHA_256();	
			String Original = Integer.toString(E);
			String E_hashData =  sha_256.encryption(Original);
			System.out.println("공개키 E 해시값: "+ E_hashData);
			
			Original = Integer.toString(N);
			String N_hashData =  sha_256.encryption(Original);
			System.out.println("공개키 N 해시값: "+ N_hashData);
			
			Original = Integer.toString(c_pm);
			String C_hashData =  sha_256.encryption(Original);
			System.out.println("공개키 N 해시값: "+ C_hashData);
			
			while(true) { //상대방에세 암호문, 공개키, 해시값을 전송
				String line = sc.nextLine();
				writer.println(c_pm);
				writer.println(E);
				writer.println(N);
				writer.println(E_hashData);
				writer.println(N_hashData);
				writer.println(C_hashData);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	class SocketThread extends Thread {
		@Override
		public void run() {
			try { //상대방이 복호화에 성공했는지 여부를 수신받는다.
				reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				String line = null;
				String line2 = null;
				String line3 = null;
				String line4 = null;
				while((line = reader.readLine()) != null) {
					line2 = reader.readLine();
					line3 = reader.readLine();
					line4 = reader.readLine();
					System.out.println("복호화 결과 : " + line);
					System.out.println("공개키 E 인증 결과 : " + line2);
					System.out.println("공개키 N 인증 결과 : " + line3);
					System.out.println("암호문 인증 결과 : " + line4);
				}
			} catch (Exception e) {
				
			}
		}
	}
	
public class SHA_256 {
		public String encryption(String str) {
			String SHA = "";
			try {
				MessageDigest sh = MessageDigest.getInstance("SHA-256"); //해시 알고리즘을 SHA-256을 타겠다는 것이다 
				sh.update(str.getBytes());
				byte byteData[] = sh.digest();
				
				StringBuffer sb = new StringBuffer();
	           
				for(int i = 0 ; i < byteData.length ; i++){
	                sb.append(Integer.toString((byteData[i]&0xff) + 0x100, 16).substring(1));
	            }
				
				SHA = sb.toString();
				
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
			return SHA;
		} 
}
	
	public static void main(String[] args) {
		new rsa_client();
	}
}
