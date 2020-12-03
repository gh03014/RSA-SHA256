개발환경: jdk8, windows 10, eclipse 

1. 이클립스 2개를 동시에 띄워서 실행하였다
2. 클라이언트는 메시지를 rsa방식과 일방향해시함수(sha-256)방식을 이용하여 이중으로 암호화 한다
3. 클라이언트는 암호문과 공개키를 서버에 전달한다
4. 서버는 공개키를 이용하여 암호문을 복호화 한다
5. 클라이언트는 서버에서 암호문을 복호화 하였는지 여부를 확인한다