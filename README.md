# ServerDBMonitor

ServerDBMonitor is a Python application designed to initialize and run a server while ensuring that a required database is correctly located and operational.

If the database is not accessible or if any errors occur during the server's runtime, the application will gracefully shut down and provide an error report.

## Features

- **Server Initialization:** Starts a server instance and monitors its status.
- **Database Connectivity Check:** Ensures that the required database is located and operational before starting the server.
- **Error Handling:** Captures and reports errors that occur during server startup or runtime.
- **Graceful Shutdown:** If the server fails to start or the database is not accessible, the application will exit with an error status.

