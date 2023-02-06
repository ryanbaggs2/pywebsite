"""
Name: Baggs, Ryan     SDEV 300-6980    Date: 07/20/2022

This program is a simple website that displays some information on the
Python, Java, and Rust programming languages using Flask. It requires
login when first loading page.
"""
# For datetime on home page and log.
import datetime

# For password hashing.
import hashlib as hl

# Flask imports for web application.
from flask import Flask, render_template, flash, request,\
    redirect, url_for, session

# The path for user login data.
USER_FILE_PATH = 'data.txt'

# The path for the attempts log.
LOG_FILE_PATH = 'log.txt'


def main():
    """
    Main function.
    """
    # Create and run the Flask application.
    create_app().run()


def create_app():
    """
    Creates instance of flask app and defines the pages.

    :return: The created instance of the Flask app.
    """
    # Create a Flask instance.
    app = Flask(__name__)

    app.secret_key = 'Something very secret'

    # Annotate and define the pages for the Flask application. When the
    # route is entered after the hosting server ip the user will be
    # taken to specified page.
    # Home page.
    @app.route('/')
    def home():
        if session.get('user_id') is not None:
            # Return the rendered template home.html from the "templates" directory.
            return render_template("home.html", date_time=get_date_time())

        return redirect(url_for("login"))

    # Login page.
    @app.route('/login', methods=['POST', 'GET'])
    def login():
        # Check if someone is already logged in.
        if session.get('user_id') is not None:
            return redirect(url_for("home"))

        if request.method == 'POST':
            # Get username and password from form.
            username = request.form['username']
            password = request.form['password']

            # Check if successful login occurred.
            if successful_login(username, password):
                # Clear the current session and set the current session to
                # the username.
                session.clear()
                session['user_id'] = username

                # Take user to home page.
                return redirect(url_for("home"))

        # Log failed attempts.
        log_attempts(
            request.remote_addr, datetime.datetime.now())

        # User did not successfully log in, take to login page.
        return render_template("login.html")

    # Registration page.
    @app.route('/registration', methods=['POST', 'GET'])
    def registration():
        if request.method == 'POST':
            # Get username and password from form.
            username = request.form['username']
            password = request.form['password']

            # Register the user.
            if successful_registration(username, password):
                # User registered, take to login page.
                return redirect(url_for("login"))

        # User did not successfully register, take to registration page.
        return render_template("registration.html")

    # Update password page.
    @app.route('/update', methods=['POST', 'GET'])
    def update():
        if request.method == 'POST':
            # Get the username from session.
            username = session.get('user_id')

            # Get the password from form.
            updated_password = request.form['password']

            if successful_pass_update(username, updated_password):
                return redirect(url_for('home'))

        return render_template('update_pass.html')

    @app.route('/logout')
    def logout():
        if session.get('user_id') is not None:
            session.pop('user_id', None)

            return render_template("logout.html")

        return redirect(url_for("login"))

    # Python page.
    @app.route('/python')
    def python():
        # Verify a user is logged in.
        if session.get('user_id') is not None:
            return render_template("python.html")

        return redirect(url_for("login"))

    # Java page.
    @app.route('/java/')
    def java():
        # Verify a user is logged in.
        if session.get('user_id') is not None:
            return render_template("java.html")

        return redirect(url_for("login"))

    # Rust page.
    @app.route('/rust/')
    def rust():
        # Verify a user is logged in.
        if session.get('user_id') is not None:
            return render_template("rust.html")

        return redirect(url_for("login"))

    return app


def get_date_time():
    """
    Returns today's date.
    """
    return datetime.date.today()


def successful_login(username, password):
    """
    Returns whether the login was successful.

    :param username: The username entered by user.
    :param password: The password entered by user.
    :return: True if the login was successful and False if not.
    """
    # Check for invalid reasons and display appropriate message for each,
    # returning False.
    if not username:
        flash('Please enter your username.')
        return False
    if not password:
        flash('Please enter your password.')
        return False
    if not check_registered(username):
        flash('You have not registered.')
        return False
    if not password_matches(
            encrypt_password(password), get_username_line(username)):
        flash("Incorrect password.")
        return False

    # User successfully logged in.
    return True


def check_registered(username):
    """
    Checks if the username has been registered.

    :param username: The username entered by user.
    :return: True if the username is registered, False if not.
    """
    # Flag.
    registered = False

    # Open the file in read mode.
    with open(USER_FILE_PATH, 'r', encoding="utf-8") as file:
        lines = file.readlines()

        # Loop through each line in file.
        for line in lines:
            if username == line.strip():
                # Username found, update flag and exit loop.
                registered = True
                break

    # Return if the username is registered.
    return registered


def password_matches(encrypted_password, username_line):
    """
    Check the password entered to see if it corresponds with its
    associated username.

    :param encrypted_password: The password entered by the user, that has
    been encrypted.
    :param username_line: The line that the username is located on.
    :return: True if the password matches, False if not.
    """
    # Check if username_line is None.
    if username_line is not None:
        count = 0

        # Open the file in read mode.
        with open(USER_FILE_PATH, 'r', encoding="utf-8") as file:
            # Get the lines of the file.
            lines = file.readlines()

            # Loop through the lines in the file.
            for line in lines:
                count += 1

                # Check if the line of the password has been reached.
                if count == username_line + 1:

                    # Check if the entered password matches the one associated with its
                    # username.
                    if encrypted_password == line.strip():
                        # Password matches what's on file.
                        return True

                    # Password checked, exit the loop.
                    break

    # Password does not match what's on file.
    return False


def get_username_line(username):
    """
    Gets the line of the username in the file.

    :param username: The username entered by the user.
    :return: The line number of the username, or None if not found.
    """
    # Initialize line_num.
    line_num = 0

    # Open the file in read mode.
    with open(USER_FILE_PATH, 'r', encoding="utf-8") as file:
        lines = file.readlines()

        # Loop through each line.
        for line in lines:
            line_num += 1

            # Check if the username is on the current line.
            if username == line.strip():
                # Username is on this line, return the line_num.
                return line_num

    # No matching username in file.
    return None


def successful_registration(username, password):
    """
    Checks if the registration was successful.

    :param username: The username entered by user.
    :param password: The password entered by user.
    :return: True if the user met all criteria and successfully registered,
    False if the user did not meet all criteria.
    """
    # Check for invalid reasons and display appropriate message for each,
    # returning False.
    if not username:
        flash('Please enter your username.')
        return False
    if not password:
        flash('Please enter your password.')
        return False
    if check_registered(username):
        flash('You are already registered.')
        return False
    if not meets_requirements(password):
        flash('Password does not meet minimum requirements.')
        return False

    # Save the username and password to the file.
    save_pass_and_user(username, encrypt_password(password))

    # Successful registration.
    return True


def meets_requirements(password):
    """
    Checks if the password entered meets requirements.

    :param password: The password entered by user.
    :return: True if the password meets all requirements, False if not.
    """
    # Check if the password contains the number of uppercase characters,
    # digits, and special characters marks by looping through all characters
    # in password.
    if (len(password) >= 12 and
            sum(c.isupper() for c in password) >= 1
            and sum(c.islower() for c in password) >= 1
            and sum(c.isdigit() for c in password) >= 1
            and sum((not c.isalnum() and
                     not c.isspace()) for c in password) >= 1):

        # Password meets requirements.
        return True

    # Password does not meet requirements.
    return False


def save_pass_and_user(username, password):
    """
    Saves the username and password to the file.

    :param username: The username entered by user.
    :param password: The password entered by user.
    """
    # Open the file in append mode.
    with open(USER_FILE_PATH, 'a', encoding="utf-8") as file:
        file.write(username + "\n")
        file.write(password + "\n")


def encrypt_password(password):
    """
    Encrypt the password using sha256 hashing.

    :param password: The password entered by user.
    :return: The encrypted password.
    """
    # Change to binary.
    password = password.encode()

    # Return the encrypted password in hexadecimal.
    return hl.sha256(password).hexdigest()


def successful_pass_update(username, updated_password):
    """
    Checks if the updated_password is valid, does not match the old password,
    it's not commonly used, and updates the old password to the
    updated_password.

    :param username: The username entered by user.
    :param updated_password: The updated password entered by user.
    :return: True if the password has been successfully updated, False if not.
    """
    # Check for invalid reasons and display appropriate message for each,
    # returning False.
    if not meets_requirements(updated_password):
        flash('Password does not meet minimum requirements.')
        return False
    if password_matches(
            encrypt_password(updated_password), get_username_line(username)):
        flash('Password cannot be the same as your old password.')
        return False
    if commonly_used(updated_password):
        flash('Password cannot be a common password, '
              'please choose a different password.')
        return False

    # Update the password in the saved file.
    update_pass(updated_password, get_username_line(username))

    # Password has been updated successfully.
    return True


def commonly_used(updated_password):
    """
    Checks if the updated_password is commonly used.
    """
    with open(USER_FILE_PATH, 'r', encoding="utf-8") as file:
        lines = file.readlines()

    for line in lines:
        if line.strip() == updated_password:
            return True

    return False


def update_pass(updated_password, username_line):
    """
    Update the old password to the updated_password.

    :param updated_password: The updated password entered by user.
    :param username_line: The line that the username is located on.
    """
    with open(USER_FILE_PATH, 'r', encoding="utf-8") as file:
        lines = file.readlines()

    lines[username_line] = updated_password + "\n"

    with open(USER_FILE_PATH, 'w', encoding="utf-8") as file:
        file.writelines(lines)


def log_attempts(ip_address, date_time):
    """
    Logs failed attempts to log in.

    :param ip_address: The ip address of the end user.
    :param date_time: The date and time that the failed login occurred.
    """
    with open(LOG_FILE_PATH, 'a', encoding="utf-8") as file:
        file.write("Failed Login, IP ADDRESS: " + ip_address
                   + ", DATE-TIME: " + date_time.strftime('%m/%d/%Y %H:%M:%S') + "\n")


main()
