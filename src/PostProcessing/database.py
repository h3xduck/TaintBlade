import sqlite3

def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def reset_database(conn):
    if conn is not None:
        # create projects table
        sql_create_function_calls_table = """ 
            CREATE TABLE function_calls (
                appearance   INTEGER    PRIMARY KEY
                                        NOT NULL,
                dll_from     TEXT (150),
                func_from    TEXT (150),
                memaddr_from INTEGER    NOT NULL,
                dll_to,
                func_to,
                memaddr_to              NOT NULL,
                arg0         INTEGER,
                arg1         INTEGER,
                arg2         INTEGER,
                arg3         INTEGER,
                arg4         INTEGER,
                arg5         INTEGER
            ); """

        sql_create_color_transformation_table = """
            CREATE TABLE color_transformation (
                derivate_color  PRIMARY KEY,
                color_mix_1,
                color_mix_2
            ); """

        sql_create_memory_colors_table = """
            CREATE TABLE memory_colors (
                inst_address INTEGER,
                func_index   INTEGER,
                mem_address  INTEGER,
                color        INTEGER NOT NULL
            ); """

        sql_create_original_colors_table = """
            CREATE TABLE original_colors (
                color    INTEGER PRIMARY KEY,
                function,
                dll
            ); """

        
        # Drop all tables
        cursor = conn.cursor()
        cursor.execute("DROP TABLE function_calls")
        cursor.execute("DROP TABLE color_transformation")
        cursor.execute("DROP TABLE memory_colors")
        cursor.execute("DROP TABLE original_colors")

        # Create tables
        create_table(conn, sql_create_function_calls_table)
        create_table(conn, sql_create_color_transformation_table)
        create_table(conn, sql_create_memory_colors_table)
        create_table(conn, sql_create_original_colors_table)

    else:
        print("Error! Cannot connect to the database.")