package rsa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Vector;
import java.security.MessageDigest;

public class rsa_server {
	
	ServerSocket serverSocket;
	Vector<SocketThread> vc;
	
	public rsa_server() {
		try {
			// 서버 소켓 생성 65536번 중에 0~1023(well known port)를 제외한 모든 포트
			serverSocket = new ServerSocket(20000);
			vc = new Vector<>();
			
			//메인쓰레드는 소켓을 accept()하고 vector에 담는 역할을 함.
			while(true) {
				System.out.println("요청 대기");
				Socket socket = serverSocket.accept(); //클라이언트 요청을 받음.
				System.out.println("요청 받음");
				SocketThread st = new SocketThread(socket);
				st.start();
				vc.add(st); 
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//소켓정보 + 타겟(run) + 식별자(id)
	class SocketThread extends Thread {	
		Socket socket;
		String id;
		BufferedReader reader;
		PrintWriter writer;
		
		public SocketThread(Socket socket) {
			this.socket = socket;
		}
		@Override
		public void run() {
			try {
				reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				writer = new PrintWriter(socket.getOutputStream(), true);
				String line = null;
				String line2 = null;
				String line3 = null;
				String line4 = null;
				String line5 = null;
				String line6 = null;
				while((line = reader.readLine()) != null) {
					line2 = reader.readLine();
					line3 = reader.readLine();
					line4 = reader.readLine();
					line5 = reader.readLine();
					line6 = reader.readLine();
					System.out.println("\n- 수신 - ");
					System.out.println("송신자로부터 받은 암호문 : "+line);
					System.out.println("송신자로부터 받은 공개키 E: " + line2);
					System.out.println("송신자로부터 받은 공개키 N: " + line3);
					System.out.println("송신자로부터 받은 공개키 E 해시값: " + line4);
					System.out.println("송신자로부터 받은 공개키 N 해시값: " + line5);
					System.out.println("송신자로부터 받은 암호문 해시값: " + line6);
					
					int c_p = Integer.valueOf(line);
					int E = Integer.valueOf(line2);
					int N = Integer.valueOf(line3);

					int D = 0;
					int p = 0;
					int q = 0;
					int L = 0;
					int r = 0;
					
					//복호화 과정
					System.out.println("\n- 복호화 과정 - ");
					for(int i = 2; i < N; i ++) { //N을 나눴을때 나머지가
						if((N % i) == 0) {        //0이 되는 소수 p를 구한다.
							p = i;
							break;
						}
					}			
					q = N / p; //N을 소수 p로 나눠서 소수 q를 구한다.
					L = (p - 1) * (q - 1);
					
					for(int i = 1; i < L; i ++) { // (E X D) mod L = 1이 
						r = (E * i) % L;          //성립되는 D를 구한다.
						if(r == 1) {
							D = i;
							break;
						}
					}
					int c_p2 = c_p;
					for( int i = 0; i < D - 1; i++) { //암호문에 D제곱을 한다.
						c_p2 = c_p2 * c_p;
					}
					int pm = c_p2 % N;  //평문 = (암호문의 D제곱) mod N 이다. 
					System.out.println("복호화를 통해 얻은 평문: " + pm);
					
					String pm_con;
					if(pm == 3) { //결과가 평문 3이 나오면 복호화에 성공했다는 의미이다.
						pm_con = "복호화 성공!";
					}
					else {
						pm_con = "복호화 실패!";
					}
					
					//무결정 인증 (SHA-256)
					System.out.println("\n- 해시값 무결성 인증 과정 - ");
					SHA_256 sha_256 = new SHA_256();
					
					String Original = Integer.toString(E);
					String E_hashData =  sha_256.encryption(Original);
					Original = Integer.toString(N);
					String N_hashData =  sha_256.encryption(Original);
					Original = Integer.toString(c_p);
					String C_hashData =  sha_256.encryption(Original);
					
					String E_hash_con; //공개키 E 해시값.
					String N_hash_con; //공개키 N 해시값.
					String C_hash_con; //암호문 해시값.
					
					if(E_hashData.equals(line4)) {
						System.out.println("송신자가 보낸 해시값과 일치합니다. 공개키 E 무결성 인증.");
						E_hash_con = "무결성 인증 성공!";
					}
					else{
						System.out.println("송신자가 보낸 해시값과 불일치 합니다. 조작된것으로 추정됩니다. 공개키 E 무결성 인증 실패");
						E_hash_con = "무결성 인증 실패!";
					}
					
					if(N_hashData.equals(line5)) {
						System.out.println("송신자가 보낸 해시값과 일치합니다. 공개키 N 무결성 인증.");
						N_hash_con = "무결성 인증 성공!";
					}
					else{
						System.out.println("송신자가 보낸 해시값과 불일치 합니다. 조작된것으로 추정됩니다. 공개키 N 무결성 인증 실패");
						N_hash_con = "무결성 인증 실패!";
					}
					
					if(C_hashData.equals(line6)) {
						System.out.println("송신자가 보낸 해시값과 일치합니다. 암호문 무결성 인증.");
						C_hash_con = "무결성 인증 성공!";
					}
					else{
						System.out.println("송신자가 보낸 해시값과 불일치 합니다. 조작된것으로 추정됩니다. 암호문 무결성 인증 실패");
						C_hash_con = "무결성 인증 실패!";
					}
					
					for (SocketThread socketThread : vc) {
						socketThread.writer.println(pm_con);
						socketThread.writer.println(E_hash_con);
						socketThread.writer.println(N_hash_con);
						socketThread.writer.println(C_hash_con);
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
public class SHA_256 {  //SHA-256알고리즘
		public String encryption(String str) {
			String SHA = "";
			try {
				MessageDigest sh = MessageDigest.getInstance("SHA-256"); //해시 알고리즘을 SHA-256을 사용한다 
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
		new rsa_server();
	}
}
