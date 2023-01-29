import sqlite3

def create_connection(db_file):
    # create a database connection to the SQLite database
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    create_connection(r"C:\Users\Marcos\source\repos\h3xduck\TFM\src\PostProcessing\db\dump.db")