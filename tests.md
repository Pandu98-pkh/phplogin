# Panduan Exploit

1. **SQL Injection**
   ```
   username: ' OR 1=1 --
   password: asdf
   ```
   Harus masuk tanpa kredensial valid.

2. **XSS**
   Daftarkan username:
   ```
   <script>alert(1)</script>
   ```
   Setelah login, alert muncul di home.php.

3. **Session Fixation**
   - Copy cookies `PHPSESSID` sebelum login.
   - Login sebagai user lain dari tab berbeda dengan cookie tersebut.
   - Tab pertama akan terautentikasi sebagai user tersebut.

