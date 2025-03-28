# User Authentication System

A simple user authentication system using Python's Tkinter for GUI, MySQL for database, and bcrypt for password hashing.

## Features
- User registration with hashed passwords
- User login validation
- Secure password storage using bcrypt
- GUI built with Tkinter
- MySQL database integration

## Installation
### Prerequisites
Make sure you have the following installed:
- Python 3
- MySQL Server
- Required Python libraries:
  ```sh
  pip install mysql-connector-python bcrypt
  ```

## Database Setup
1. Create a MySQL database named `user`.
2. Create a `users` table using the following SQL query:
   ```sql
   CREATE TABLE users (
       id INT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(255) NOT NULL UNIQUE,
       password VARCHAR(255) NOT NULL
   );
   ```

## Usage
Run the script using Python:
```sh
python app.py
```
This will open a GUI window where users can register and log in.

## How It Works
- The user enters a username and password to register.
- The password is hashed using bcrypt before storing it in the database.
- During login, the entered password is verified against the hashed password stored in the database.

## Project Structure
```
├── app.py  # Main script
├── README.md  # Documentation
```

## License
This project is open-source and available under the MIT License.
