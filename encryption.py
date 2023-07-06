import os
import firebase_admin
from flask import Flask, flash, request, redirect, url_for, render_template, session, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from firebase_admin import credentials, firestore, initialize_app

cred = credentials.Certificate("privatekey.json")
default_app = initialize_app(cred)
db = firestore.client()

with open('filekey.key', 'rb') as filekey:
    key = filekey.read()

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = "hello"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get("username") is None: # login page can only be accessed if the user is not logged in
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            users = db.collection("users").where("username", "==", username).stream()

            for user in users:
                userdict = user.to_dict()
                dbpass = userdict.get("password")

            if not check_password_hash(dbpass, password): # if the passwords dont match then deny the login and redirect them back to the login page
                flash("wrong details buddy")
                return redirect("/")

            session['username'] = username

            return redirect('/upload') # otherwise redirect to the upload page
        return render_template("index.html")
    else:
        flash("already logged in")
        return redirect("/upload")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form["register"] == "register": # if the register button in the login page is pressed render the register page
            return render_template("register.html")
        username = request.form.get('username')
        password = request.form.get('password')

        password = generate_password_hash(password, method='sha256') # hash password

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) # generate a new private key for the user and save it locally onto the machine
        pem = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pkem = private_key.private_bytes(encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))

        f = open(username + "_private_key.pem", "w+")
        f.write(pkem.decode("utf-8"))
        f.close()

        data = {
            "username": username,
            "password": password,
            "public_key": pem
        }

        db.collection("users").add(data) # upload data to the database for later use

        flash("user registered")
        flash("a private key has been generated for this user, it will be saved locally onto your machine")
        return redirect("/")
    else:
        return render_template("register.html")

@app.route('/log_out', methods=['GET', 'POST'])
def log_out():
    session["username"] = None
    flash("logged tf out")
    return redirect("/")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if session.get("username") is not None: # if user is not logged in send back to log in page
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)

            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return render_template("image.html", filename=filename)

        return render_template("basic_upload.html", username=session.get("username"))
    else:
        flash("not allowed")
        return redirect(request.url)

@app.route('/<filename>')
def display_image(filename):
    return redirect(url_for('static', filename='uploads/' + filename), code=301) # display the image given

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        users = db.collection("users").where("username", "==", request.form["username"]).stream() # grab user from database

        for user in users:
            userdict = user.to_dict()
            username = userdict.get("username")
            public_key = userdict.get("public_key")

        if username is None: # if user does not exist redirect to upload page
            flash("please select an existing user")
            return redirect(request.url)
        
        filename = request.form['encrypt']

        with open('static/uploads/' + filename, 'rb') as file:
            original = file.read()

        public_key = serialization.load_pem_public_key(public_key) # grab public key and deserialize it

        f = Fernet(key)
        encrypted = f.encrypt(original) # encrypt file with Fernet key
        
        encryptedkey = public_key.encrypt(key, padding.OAEP( # encrypt Fernet key with public key
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

        data = {
            "recipient": request.form["username"],
            "key": encryptedkey
        }

        db.collection("keys").add(data) # add to database

        with open('static/uploads/' + filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted) # write to file
        
        flash('file ecnrypted!')
        return redirect('/upload')

    return redirect(request.url)
    
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        keys = db.collection("keys").where("recipient", "==", session["username"]).stream() # recieve encrypted key from database

        for keya in keys:
            keydict = keya.to_dict()
            public_key = keydict.get("key")

        filename = request.form['decrypt']

        with open('static/uploads/' + filename, 'rb') as file:
            encrypted = file.read() # read file

        with open(session["username"] + "_private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=b'mypassword') # serialize private key
        
        decrypted_key = private_key.decrypt(public_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        f = Fernet(decrypted_key)
        decrypted = f.decrypt(encrypted) # after decrypting Fernet key with private key, decrypt file with Fernet key

        with open("static/uploads/" + filename, 'wb') as decrypted_file:
            decrypted_file.write(decrypted) # write decrypted file back to file
        
        flash('file decnrypted!')
        return render_template("image.html", filename=filename)

    return redirect(request.url)

if __name__ == "__main__":
    app.run(threaded=True)