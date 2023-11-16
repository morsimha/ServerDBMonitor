# main.py

import sys
import server
import database

if __name__ == '__main__':
    server = server.Server()
    database = database.Database()

    # Run should fail for db failure, or errors while listening.
    status = database.locate_database
    if status:
        try:
            server.run()
        except Exception as e:
            print(f"-F- Error occurred while running server: {e}")
            status = False

    if not status:
        print("-F- Run was not completed successfully.")
        sys.exit(1)
