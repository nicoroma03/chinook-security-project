import sqlite3
from datetime import datetime, timezone

DB_PATH = "Chinook_Sqlite.sqlite"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

#=======
# Users
#=======

def create_user(username: str, employee_id:int, password_hash: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO Users (username, employee_id, password_hash)
        VALUES (?, ?, ?)
        """,
        (username, employee_id, password_hash)
    )

    conn.commit()
    conn.close()

def set_user_password_hash(username: str, password_hash: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "UPDATE Users SET password_hash = ? WHERE username = ?",
        (password_hash, username)
    )

    conn.commit()
    conn.close()

def get_user_password_hash(username: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT password_hash FROM Users WHERE username = ?",
        (username,)
    )

    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    return row["password_hash"]

def get_user_id(username: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM Users WHERE username = ?",
        (username,)
    )

    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    return row["id"]

def get_user_employee_id(username: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT employee_id FROM Users WHERE username = ?",
        (username,)
    )

    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    return row["employee_id"]


#==========
# Employee
#==========

def get_employee_title(id: int):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT Title FROM employee WHERE EmployeeId = ?",
        (id,)
    )

    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    return row["title"]

#===============
# RefreshTokens
#===============

def store_refresh_token_hash(user_id: int, token_hash: str, expires_at):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO RefreshTokens (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
        """,
        (user_id, token_hash, expires_at)
    )

    conn.commit()
    conn.close()


def get_expiration_of_token_hash(token_hash: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT expires_at
        FROM RefreshTokens
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    return row["expires_at"]


def delete_refresh_token_by_hash(token_hash: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM RefreshTokens WHERE token_hash = ?",
        (token_hash,)
    )

    conn.commit()
    conn.close()


def delete_refresh_token_by_user(user_id: int):
    conn = get_connection()
    try:
        cur = conn.cursor()

        cur.execute(
            "DELETE FROM RefreshTokens WHERE user_id = ?",
            (user_id,)
        )

        conn.commit()
    finally:
        conn.close()

#===========
# Customers
#===========

def get_customers_for_employee(employee_id: int, filters: dict):
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # Base query: strict scoping to the logged-in employee
        sql = """
            SELECT CustomerId, FirstName, LastName, Company, Email, Phone, City, Country
            FROM Customer 
            WHERE SupportRepId = ?
        """
        params = [employee_id]

        # Dynamically append filters if they exist
        if filters.get('name'):
            sql += " AND (FirstName LIKE ? OR LastName LIKE ?)"
            search_name = f"%{filters['name']}%"
            params.extend([search_name, search_name])
            
        if filters.get('company'):
            sql += " AND Company LIKE ?"
            params.append(f"%{filters['company']}%")
            
        if filters.get('city'):
            sql += " AND City LIKE ?"
            params.append(f"%{filters['city']}%")
            
        if filters.get('country'):
            sql += " AND Country LIKE ?"
            params.append(f"%{filters['country']}%")

        # Execute
        cur.execute(sql, params)
        rows = cur.fetchall()
        
        # Convert rows to list of dicts for JSON response
        return [dict(row) for row in rows]
        
    finally:
        conn.close()
