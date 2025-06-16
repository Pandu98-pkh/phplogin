# Insecure PHP‑Login

A deliberately vulnerable PHP/MySQL login application for Spring 2025 ACK3HAB3 hands‑on project.

---

## 1  Lab Layout

```
phplogin_lab/
├── db.php
├── index.php
├── register.php
├── authenticate.php
├── home.php
├── profile.php
├── logout.php
├── tests.md
└── README.md
```

---

## 2  Requirements
1. **Windows**
| Item | Version |
|------|---------|
| **XAMPP** | PHP 8.x + MySQL 8.x bundle |
| Browser | Chrome / Edge / Firefox |
2. **Linux**
| Component | Tested on |
|-----------|-----------|
| Apache Web Server | apache2 (2.4.x) |
| PHP | php 8.x (with `mysqli` extension) |
| MySQL / MariaDB | mysql‑server 8.x **or** mariadb‑server 10.x |
| Optional GUI | **phpMyAdmin** |
---

## 3  Setup Steps

1. **Install XAMPP**

   * Download from <https://www.apachefriends.org>.  
   * Run the installer, accept defaults.  
   * Launch **XAMPP Control Panel** and click **Start** for *Apache* and *MySQL*.

2. **Clone the lab**

   * Clone the project:

     ```
     git clone https://gitlab.com/cretoxyrhina/phplogin.git
     ```  
   * Move the folder to:

     ```
     C:\xampp\htdocs\phplogin
     ```

3. **Create the database in phpMyAdmin**

   1. Open <http://localhost/phpmyadmin>.  
   2. Click **New** → type **phplogin** → **Create**.  
   3. Select the new DB, open the **SQL** tab, paste & run:

      ```sql
      CREATE TABLE accounts (
        id       INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(50)  NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        fullname VARCHAR(100) DEFAULT '',
        email    VARCHAR(100) DEFAULT ''
      );

      INSERT INTO accounts (username,password,fullname,email) VALUES
        ('admin','admin123','Admin User','admin@example.com'),
        ('test','test123','Test User','test@example.com');
      ```

   *The default `db.php` expects **root** with no password—the XAMPP default.*

4. **Browse to the app**

   Open <http://localhost/phplogin/>.  
   Log in with **admin / admin123** to confirm everything runs.

---

## 4  Objectives & Checkpoints

| CP | Goal | Edit these files |
|----|------|------------------|
| 0 | Verify exploits in `tests.md` all work | — |
| 1 | Harden authentication (POST, CSRF, prepared stmt, salted hashes) | `index.php`, `register.php`, `authenticate.php` |
| 2 | Secure sessions & cookies | `authenticate.php`, `home.php`, `logout.php` |
| 3 | Fix XSS & output encoding | `home.php`, `profile.php` |
| 4 | Use least‑privilege DB user + silent logging | `db.php` |

Each file contains `// TODO Cx‑y` comments that line up with the checkpoints
above.

---

## 5  Working Through the Lab

1. **Exploit first.**  
   Follow every attack in **tests.md** (SQL‑i, XSS, session fixation).
2. **Patch the code.**  
   Replace the matching TODO block with your fix.
3. **Retest.**  
   The exploit should now fail.
4. **Commit.**  
   Save and documentate your work.

---

## 6  Troubleshooting

* **Blank page / 500 error** – Check *Apache*’s **error.log** in
  `C:\xampp\apache\logs`.
* **Headers already sent** – Make sure no HTML or echo precedes
  `session_start()` or `header()`.
* **Cannot connect to DB** – Confirm *MySQL* module is running and `db.php`
  credentials match your setup.

