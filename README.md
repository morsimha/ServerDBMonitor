# ServerDBMonitor

ServerDBMonitor is a Python application designed to initialize and run a server listening on a specific port, making sure a secure and valid communications are conducted.

This server communicates with a C++ client I wrote - https://github.com/morsimha/ClientDBMonitor

This project was made as a final university course - "Defensive System Development" , grade A+.

## Features

- **Server Initialization:** Starts a server instance and monitors its status.
- **Database Connectivity Check:** Ensures that the required database is located and operational before starting the server.
- **Error Handling:** Captures and reports errors that occur during server startup or runtime.
- **Graceful Shutdown:** If the server fails to start or the database is not accessible, the application will exit with an error status.

# Demo Video
Watch the demo video below by clicking on the image to see a Server/Client communication in action:

 [![Hangman Game Demo](https://img.youtube.com/vi/Bp3-0G_OEbI/0.jpg)](https://youtu.be/Bp3-0G_OEbI)”
