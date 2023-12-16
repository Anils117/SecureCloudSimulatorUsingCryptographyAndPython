import os
from flask import Flask, request, render_template, flash,redirect, send_file, url_for, session
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from zipfile import ZipFile
import shutil
import secrets
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto import Random
from s3 import *
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re




app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(16)


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'CloudSecureSimulator'

mysql = MySQL(app)


# @app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s AND password = % s', (username, password, ))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            msg = 'Logged in successfully !'
            return render_template('index.html', msg = msg)
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)



@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s)', (username, password, email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)



@app.route('/')
def home():
    return render_template('home.html', decrypted_text=None, encrypted_text=None)



@app.route('/index')
def index():
    return render_template('index.html', decrypted_text=None, encrypted_text=None)



app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['DOWNLOAD_FOLDER'] = os.path.join(app.root_path, 'downloads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(app.config['DOWNLOAD_FOLDER']):
    os.makedirs(app.config['DOWNLOAD_FOLDER'])




def generate_key():
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

def load_key(key_path):
    return open(key_path, 'rb').read()



@app.route('/uploadtoaws')
def uploadtoaws():
    return render_template('uploadtoaws.html', decrypted_text=None, encrypted_text=None)


@app.route('/encryptfernet', methods=['POST'])
def encrypt_file_fernet():

    # check if the post request has the file part
    if 'file' not in request.files:
        return "No file uploaded"

    file = request.files['file']
    if file.filename == '':
        return "No file selected"

    # Check if the file type is allowed
    if file and allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)

        # Save the file to the upload folder
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Generate a new encryption key and save it to a file named 'key.key'
        key = Fernet.generate_key()
        keyfilename = filename + '.key'
        with open(keyfilename, 'wb') as key_file:
            key_file.write(key)

        # Create a Fernet instance with the generated key
        fernet = Fernet(key)

        # Read the contents of the original file
        with open(filepath, 'rb') as original_file:
            original = original_file.read()

        # Encrypt the file contents
        encrypted = fernet.encrypt(original)

        # Save the encrypted file to a file named after the original file
        with open(filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        # Create a zip file containing the encrypted file and the encryption key
        filen = filename.split(".")[0]    
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], filen + '.zip')
        with ZipFile(zip_path, 'w') as zip_file:
            zip_file.write(filename)
            zip_file.write(keyfilename)
        zip_file.close()

        # Remove the original file, the encrypted file, and the encryption key
        os.remove(filename)
        os.remove(filepath)
        os.remove(keyfilename)

        # Send the decrypted file to the user
        response = send_file(zip_path, as_attachment=True)
        
        return response
    else:
        # If the file type is not allowed, redirect to the home page
        return render_template('index.html')



@app.route('/decryptfernet', methods=['GET', 'POST'])
def decrypt_file_fernet():
    if request.method == 'POST':
        if 'file' not in request.files or 'key' not in request.files:
            return "No file uploaded"

        file = request.files['file']
        key = request.files['key']
        if file.filename == '' or key.filename == '':
            return "No file selected"
        
        # Save the files to disk
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        keyname = secure_filename(key.filename)
        key.save(os.path.join(app.config['UPLOAD_FOLDER'], keyname))
        
        # Decrypt the file
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], keyname)
        output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
        key = load_key(key_path)
        fernet = Fernet(key)
        with open(input_path, 'rb') as encrypted_file:
            encrypted = encrypted_file.read()
        decrypted = fernet.decrypt(encrypted)
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)

        os.remove(input_path)
        os.remove(key_path)
        # Send the decrypted file to the user
        return send_file(output_path, as_attachment=True)
    else:
        return render_template('decrypt.html')
    


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from flask import Flask, request, send_file, render_template
from werkzeug.utils import secure_filename
import os



def generate_default_key():
    # Generate a default key with appropriate size
    key = os.urandom(32)  # 32 bytes for AES-256
    return key


def encrypt_file_aes(input_path, output_path, key):
    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        iv = os.urandom(16)  # Generate a random initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Write IV to the output file
        outfile.write(iv)

        # Encrypt the file
        while True:
            chunk = infile.read(1024)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                padder = padding.PKCS7(128).padder()
                chunk = padder.update(chunk) + padder.finalize()
            outfile.write(encryptor.update(chunk) + encryptor.finalize())

def decrypt_file_aes(input_path, output_path, key):
    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        iv = infile.read(16)  # Read IV from the input file
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the file
        while True:
            chunk = infile.read(1024)
            if len(chunk) == 0:
                break
            decrypted_chunk = decryptor.update(chunk) + decryptor.finalize()
            outfile.write(decrypted_chunk)

@app.route('/encryptaes', methods=['POST'])
def encrypt_file_with_default_key():
    if 'file' not in request.files:
        return "No file uploaded"

    file = request.files['file']
    if file.filename == '':
        return "No file selected"

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    key = generate_default_key()

    output_path = "(enc)" + filename
    encrypt_file_aes(filepath, output_path, key)

    # Create a zip file containing the encrypted file and key
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], "(enc)" + filename + '.zip')
    with ZipFile(zip_path, 'w') as zip_file:
        zip_file.write(output_path)

    os.remove(filepath)
    os.remove(output_path)

    # Write the default key to a file
    keyfilename = filename + '.key'
    with open(keyfilename, 'wb') as key_file:
        key_file.write(key)

    with ZipFile(zip_path, 'a') as zip_file:
        zip_file.write(keyfilename)

    os.remove(keyfilename)

    return send_file(zip_path, as_attachment=True)

@app.route('/decryptaes', methods=['POST'])
def decrypt_file_with_default_key():
    if 'file' not in request.files or 'key' not in request.files:
        return "No file uploaded"

    file = request.files['file']
    key_file = request.files['key']

    if file.filename == '' or key_file.filename == '':
        return "No file selected"

    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    keyname = secure_filename(key_file.filename)
    key_file.save(os.path.join(app.config['UPLOAD_FOLDER'], keyname))

    with open(os.path.join(app.config['UPLOAD_FOLDER'], keyname), 'rb') as key_file:
        key = key_file.read()

    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], "(dec)" + filename)
    decrypt_file_aes(input_path, output_path, key)

    os.remove(input_path)
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], keyname))

    return send_file(output_path, as_attachment=True)



@app.route('/text-encryption', methods=['GET', 'POST'])
def text_encryption():
    if request.method == 'POST':
        text = bytes(request.form.get('en-text'), 'utf-8')
        # perform encryption on the text here and get the encrypted text and key
        key = Fernet.generate_key()
        f=Fernet(key)
        encrypted_text = f.encrypt(text).decode()
        key=key.decode()
        return render_template('index.html', encrypted_text=encrypted_text, key=key, text=text)
    return render_template('index.html')

@app.route('/decrypt_text',  methods=['GET', 'POST'])
def decrypt_text():
    if request.method == 'POST':
        text = bytes(request.form.get('en-text'), 'utf-8')
        key = request.form.get('key')
        # perform decryption
        try:
            f=Fernet(key)
            decrypted_text = f.decrypt(text).decode()
        except:
            decrypted_text = "Incorrect Input: check your text and key!!"
        return render_template('index.html', decrypted_text=decrypted_text)
    return render_template('index.html')

@app.route('/clear_flask_vars', methods=['POST'])
def clear_flask_vars():
    session.clear()  # clear all session variables
    return redirect(url_for('index', _anchor='textdecryp'))

@app.route('/clear')
def clear():
    
    # Clear uploads folder
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))
    
    # Clear downloads folder
    for filename in os.listdir(app.config['DOWNLOAD_FOLDER']):
        file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))
    
    flash('Folders cleared successfully', 'success')
    return redirect(url_for('index'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}



#------------------------------------------------------------------------------------------

ALLOWED_EXTENSIONS = set(['xls', 'xlsx', 'xlsm','txt','png','jpg','jpeg','pdf'])
 
 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 


@app.route('/upload_files_to_s3', methods=['GET', 'POST'])
def upload_files_to_s3():
    if request.method == 'POST':
 
        # No file selected
        if 'file' not in request.files:
            flash(f' *** No files Selected', 'danger')
 
        file_to_upload = request.files['file']
        content_type = request.mimetype
 
        # if empty files
        if file_to_upload.filename == '':
            flash(f' *** No files Selected', 'danger')
 
        # file uploaded and check
        if file_to_upload and allowed_file(file_to_upload.filename):
 
 
            file_name = secure_filename(file_to_upload.filename)
 
            print(f" *** The file name to upload is {file_name}")
            print(f" *** The file full path  is {file_to_upload}")
 
            bucket_name = "anilkumarmallembucket"
 
            s3_upload_small_files(file_to_upload, bucket_name, file_name,content_type )
            flash(f'Success - {file_to_upload} Is uploaded to {bucket_name}', 'success')
 
        else:
            flash(f'Allowed file type are - xls - xlsx - xlsm.Please upload proper formats...', 'danger')
 
    return redirect(url_for('uploadtoaws'))




@app.route('/download_files_from_s3', methods=['GET', 'POST'])
def download_file_from_s3():
    bucket_name = request.form['bucketname']
    object_name = request.form['objectname']
    local_file_path = request.form['filename']
    try:
        # Initialize S3 client
        s3_client = boto3.client('s3')
        
        # Download file
        s3_client.download_file(bucket_name, object_name, local_file_path)

        flash(f'Success - File is Downloaded', 'success')
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Failure - File Downlaod Failed', 'danger')
    return redirect(url_for('uploadtoaws'))




if __name__ == '__main__':
    app.run(debug=True)
