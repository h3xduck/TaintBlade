import sqlite3
import constant
import database
import time

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

def insert_color_transformation(conn, transformation):
    sql = ''' INSERT INTO color_transformation(derivate_color, color_mix_1, color_mix_2)
              VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, transformation)
    conn.commit()
    return cur.lastrowid

def insert_memory_colors(conn, colors):
    sql = ''' INSERT INTO memory_colors(inst_address, func_index, mem_address, color)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, colors)
    conn.commit()
    return cur.lastrowid

def insert_original_colors(conn, colors):
    sql = ''' INSERT INTO original_colors(color, function, dll, func_index)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, colors)
    conn.commit()
    return cur.lastrowid

def load_dump_files(conn):
    start = time.time()
    with open(constant.FUNCTION_CALL_FILENAME) as file:
        for line in file:
            tokens = line.rstrip().split(constant.DUMP_FILE_INTER_SEPARATOR)
            #print(tokens)
            insert_function_call(conn, tokens)
    end = time.time()
    print("Finished inserting function calls dump. Elapsed time: "+str(end-start))
    
    with open(constant.COLOR_TRANSFORMATION_FILENAME) as file:
        for line in file:
            tokens = line.rstrip().split(constant.DUMP_FILE_INTER_SEPARATOR)
            #print(tokens)
            insert_color_transformation(conn, tokens)
    end = time.time()
    print("Finished inserting color transformations dump. Elapsed time: "+str(end-start))
            
    with open(constant.TAINTED_MEMORY_FILENAME) as file:
        for line in file:
            tokens = line.rstrip().split(constant.DUMP_FILE_INTER_SEPARATOR)
            #print(tokens)
            inst_addr = tokens[0]
            func_index = tokens[1]
            for i in range(2, len(tokens), 2):
                #print(tokens[i:i+2])
                insert_memory_colors(conn, [inst_addr, func_index, tokens[i], tokens[i+1]])
    end = time.time()
    print("Finished inserting memory taint dump. Elapsed time: "+str(end-start))
    
    with open(constant.ORIGINAL_COLORS_FILENAME) as file:
        for line in file:
            tokens = line.rstrip().split(constant.DUMP_FILE_INTER_SEPARATOR)
            #print(tokens)
            insert_original_colors(conn, tokens)
    end = time.time()
    print("Finished inserting original colors dump. Elapsed time: "+str(end-start))


def main():
    conn = create_connection(r"C:\Users\Marcos\source\repos\h3xduck\TFM\src\PostProcessing\UI\db\dump.db")
    
    database.reset_database(conn)
    
    load_dump_files(conn)
   

if __name__ == '__main__':
    main()

