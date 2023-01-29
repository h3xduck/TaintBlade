import sqlite3
import constant
import database

def create_connection(db_file):
    # create a database connection to the SQLite database
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print("Connected to sqlite V" + sqlite3.version)
    except Error as e:
        print("Error connecting to the database:" + e)
    
    return conn


def insert_function_call(conn, function_call):
    sql = ''' INSERT INTO function_calls(appearance, dll_from, func_from, memaddr_from, dll_to, func_to, memaddr_to, arg0, arg1, arg2, arg3, arg4, arg5)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, function_call)
    conn.commit()
    return cur.lastrowid




def main():
    conn = create_connection(r"C:\Users\Marcos\source\repos\h3xduck\TFM\src\PostProcessing\db\dump.db")
    
    database.reset_database(conn)

    with open(constant.FUNCTION_CALL_FILENAME) as file:
        for line in file:
            tokens = line.rstrip().split(constant.DUMP_FILE_INTER_SEPARATOR)
            #print(tokens)
            insert_function_call(conn, tokens)


if __name__ == '__main__':
    main()

