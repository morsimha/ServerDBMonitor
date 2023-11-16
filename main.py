import sys
import server
import database


# Main function - runs the server.
if __name__ == '__main__':
    server = server.Server()
    database = database.Database()

    # run should fail only for db failure, else it should listen.
    if database.create_database:
        server.run()
    else:
        print("-F- Run was not completed successfully.")
        sys.exit(1)

