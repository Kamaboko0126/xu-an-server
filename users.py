import sqlite3


def create_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Create table if it does not exist
    c.execute('''
    CREATE TABLE IF NOT EXISTS users
    (firstName text, lastName text, email text, password text, publicKey text, Verified boolean DEFAULT 0)
    ''')

    # Save (commit) the changes
    conn.commit()

    # Close the connection
    conn.close()


if __name__ == "__main__":
    create_db()
