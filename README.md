# REPORT 

### 0. Index
1. [[#1. Summary]]
2. [[#2. Technology Stack]]
3. [[#3. Implementation of Functional Requirements]]
4. [[#4. Security & Privacy Practices]]
5. [[#5. Security concerns]]
6. [[#6. Running the project]]


### 1. Summary

This project implements a secure backend system for the Chinook media store database. The system features a RESTful API architecture with a clear separation between frontend and backend , complying with the security and privacy by design principles required by the module. 

### 2. Technology Stack
- **Backend Language:** Python 3.13.11
  *an exaustive list of all python libraries used is provided in the requirements.txt file*
- **Web Framework:** [FastAPI](https://fastapi.tiangolo.com/) ([repository link](https://github.com/fastapi/fastapi))
- **Database:** [SQLite](https://sqlite.org/)
- **Frontend Language**
	- HTML
	- CSS
	- Javascript
### 3. Implementation of Functional Requirements
**3.1 Authentication & User Management**
- **Requirement:** Login as Employee with default password "Jo5hu4!".
	- **Implementation:** The system currently implements a custom "Create New User" flow (`/create_new_user` endpoint) that requires "Jo5hu4!" as a master authorization key to register new accounts.
	  The new user will then be able to login with his username of choice and the password "Jo5hu4!".
- **Requirement:** Password Complexity Rules (6-14 chars, 3 of 4 categories: upper, lower, numbers, symbols).
	- **Implementation:** The `validate_password_complexity` function in `security.py` enforces these exact rules using regex checks (`[A-Z]`, `[a-z]`, `[0-9]`, `[^A-Za-z0-9]`) and length validation.
- **Requirement:** Password Change & History (No reuse of current password).
	- **Implementation:** The `/change_password` endpoint verifies the new password against the stored hash. If `verify_password(new_password, stored_hash)` returns `True`, the change is rejected, ensuring the new password is effectively different from the current one.
**3.2 Authorization & Access Control**
- **Requirement:** Managers see all customers; Employees see only their own.
	- **Implementation:** The function `is_manager` determines role based on the employee's `Title`.
	- **Gap with the requirement:** Up to this moment managers see only their direct customers, like every other user. This is because in the database query `get_customers_for_employee` in `db.py` currently _always_ filters by `SupportRepId`.
	- **Possible future fix:** Modify `db.py` to accept an optional `employee_id`. If `None` is passed (for managers), remove the `WHERE SupportRepId = ?` clause.
**3.3 Session Management**
- **Requirement:** Tokens expire every 5 minutes; Auto-refresh for managers; Logout on inactivity for users.
	- **Implementation:**
		- **Managers:** Access tokens last 5 minutes. The frontend `chinook_portal.html` includes a timer that hits the `/refresh` endpoint automatically every 4 minutes.
		- **Employees:** Access tokens last 2 minutes. The frontend includes a `sessionTimer` that forces a logout after 2 minutes of inactivity.
### 4. Security & Privacy Practices
**4.1 Secure Password Storage**
- **Practice:** Passwords are never stored in plain text.
- **Implementation:** The project uses **bcrypt**(`bcrypt.hashpw` with `gensalt()`) in `security.py`. Bcrypt is an adaptive hashing function that is resistant to rainbow table attacks and brute-force attempts due to its work factor (salting and key stretching).
**4.2 Web Security & Injection Prevention**
- **SQL Injection:**
    - **Implementation:** All database interactions in `db.py` use **parameterized queries** (e.g., `WHERE SupportRepId = ?`). This ensures that user input is treated strictly as data, not executable code, completely neutralizing SQL injection attacks.
- **Code Injection / XSS:**
    - **Implementation:** Input validation is handled via Pydantic models in `models.py`. The `validate_search_content` validator uses a **whitelist approach** (`^[a-zA-Z0-9\s\-\'\.]+$`), rejecting any input containing dangerous characters (like `<script>`,`;`, or `DROP TABLE`).
**4.3 Logging & Traceability**
- **Implementation:** A robust logging system is implemented in `server.py` with distinct log files:
    - `activity.log`: Tracks functional actions (Login, Search) for audit trails.
    - `security.log`: Tracks suspicious events (Failed logins, Invalid tokens).        
    - `errors.log`: Captures system exceptions for debugging.
- **Privacy Note:** The logs avoid recording sensitive data like passwords. Token values are masked (`mask_token` function) to prevent leakage.
**4.4 Privacy & Data Protection**
- **Data Minimization:** The API returns specific fields (`FirstName`, `Company`, `Email`) rather than `SELECT *`.
- **Privacy Risk:** The "Address" and "Phone" fields constitute Personally Identifiable Information (PII).
    - **Possible Improvement:** If not strictly necessary we could remove these columns from the `SELECT` statement in `db.py` (Data Minimization).
**4.5 Error Handling**
- **Implementation:** The API uses `try...except` blocks globally. Standard Python exceptions are caught and converted into generic `HTTPException(status_code=500)` responses.
- **Benefit:** This prevents "Stack Traces" from leaking to the client, which could otherwise reveal internal file paths or logic to an attacker.

### 5. Security concerns
- Dependencies: Of the libraries used in the backend none have recent vulnerabilites (according to the [pyscan](https://github.com/ohaswin/pyscan tool) :). A more detailed report is visible in the requirements-security.txt file.
#### Other risks i am aware of:

| **Risk Identified**       | **Severity** | **Description**                                                                                                                                                                                                                                                 | **Proposed Improvement**                                                                                                                                                                 |
| ------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Hardcoded Secrets**     | **High**     | The master password "Jo5hu4!" is visible in the code                                                                                                                                                                                                            | The easiest improvement would be to export it as an environment variable. A better solution would be to use a dedicated Secret Manager or vault like Hashicorp Vault or Azure Key Valut. |
| **TLS Security**          | **High**     | Now the communication between frontend and backend is using unencrypted http. Being that the security of the system relies on the token sent via http this is a huge vulnerability.<br>Possible risks are:<br>- **Credential Theft**<br>- **Session Hijacking** | Force the use of HTTPS.<br>This can be done with a self signed certificate and handle the encryption in the `server.py` or even better to set up a reverse proxy.                        |
| **Environment Variables** | **Medium**   | JWT secrets are saved in or environment variables that might be mishandled.                                                                                                                                                                                     | (See Hardcoded Secrets Improvement)                                                                                                                                                      |
| **Token Storage**         | **Medium**   | Tokens are stored in frontend variables/memory. Cross-Site Scripting (XSS) could theoretically access them.                                                                                                                                                     | Store the `refresh_token` in an `HttpOnly` `Secure` Cookie, preventing JavaScript access.                                                                                                |

other vulnerabilities are highlighted in the bandit-report.txt file, created using the [bandit](https://bandit.readthedocs.io/en/latest/) tool.

### 6. Running the project

- Server:
  To run the server it should be enough to have python 3.13.11
  Then open a terminal and run the command 
	1. `source venv/bin/activate`
	2. `python3 server.py`
- Client:
  Being the client an html page is enough to open it with your preferred browser.

  >[!info] AI USAGE
  > As i am not a proficient in web developing i used AI to help me  with the development of the web page (HTML CSS JAVASCRIPT).
  > I tried to keep the page and the scripts as simple as possible to avoid security risks, so the result is an extremly simple page.
  > Nonetheless the page should still be usable from all devices and smartphones
  
  




