from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask(__name__)
app.secret_key = 'keep it secret, keep it safe'
bcrypt = Bcrypt(app)


@app.route("/")
def index():
    if 'user_info' in session:
        return redirect ('/wall')
    return render_template("index.html")


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')


@app.route("/", methods=["POST"])
# --------------------------------------------------begin "/"=POST
def registration():
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash("<div class='ohno'>Please enter valid email</div>")
    if not NAME_REGEX.match(request.form['first_name']):
        is_valid = False
        flash("<div class='ohno'>First name must contain only letters</div>")
    if len(request.form['first_name']) < 2:
        is_valid = False
        flash("<div class='ohno'>First name must contain at least two letters</div>")
    if not NAME_REGEX.match(request.form['last_name']):
        is_valid = False
        flash("<div class='ohno'>Last name must contain only letters</div>")
    if len(request.form['last_name']) < 2:
        is_valid = False
        flash("<div class='ohno'>Last name must contain at least two letters</div>")

    if len(request.form['password']) < 8:
        is_valid = False
        flash("<div class='ohno'>Password must be between 8-15 characters</div>")
    if len(request.form['password']) > 15:
        is_valid = False
        flash("<div class='ohno'>Password must be between 8-15 characters</div>")
    if request.form['confirmpassword'] != request.form['password']:
        is_valid = False
        flash("<div class='ohno'>Passwords must match</div>")
    if is_valid == False:
        return redirect('/')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL("pirateWall")
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s,%(last_name)s, %(email)s, %(password_hash)s, NOW(), NOW());"
        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['email'],
            "password_hash": pw_hash,
        }
        new_user_info = mysql.query_db(query, data)
        session['user_info'] = new_user_info[0]

        # --------------------------------------------------end /=POST
        return redirect('/wall')


# -----------------------------------------begin /login=POST
@app.route("/login", methods=['POST'])
def login():
    mysql = connectToMySQL("pirateWall")
    query = "SELECT * FROM users WHERE email=%(email)s;"
    data = {
        "email": request.form["email"]
    }
    result = mysql.query_db(query, data)
    if len(result) > 0:
        # assuming we only have one user with this username, the user would be first in the list we get back
        # of course, we should have some logic to prevent duplicates of usernames when we create users
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session["user_info"] = result[0]
            return redirect('/wall')
        else:
            flash("<div class='ohno'>You could not be logged in</div>")
    else:
        flash("<div class='ohno'>You could not be logged in</div>")
        return redirect('/')

def checklogin():
    if "user_info" not in session:
        flash("<div class='ohno'>Please log in</div>")
        return False
    return True

@app.route("/logout")
def logout():
    if "user_info" in session:
        session.pop("user_info")
    return redirect("/")

@app.route("/wall")
def success():
    if not checklogin():
        return redirect('/')
    user_info = session['user_info']
# ------- search for allUsers to put on the right side on wall page
    mysql = connectToMySQL("pirateWall")
    query = "SELECT * FROM users;"
    allUsers = mysql.query_db(query)
# ------- search for all messages that are for recepient
    mysql = connectToMySQL("pirateWall")
    queryTwo="SELECT messages.id, messages.message, messages.senders_id, messages.created_at, users.first_name FROM messages JOIN users ON senders_id = users.id WHERE messages.recepient_id = %(recepient_id)s;"
    dataTwo ={
        "recepient_id": user_info['id']
    }
    allMessagesForRecepient=mysql.query_db(queryTwo,dataTwo)
    return render_template("wall.html", allUsers=allUsers, allMessagesForRecepient=allMessagesForRecepient, user_info=user_info)

@app.route("/send", methods=['POST'])
def sendMessage():
    user_info = session['user_info']
    mysql = connectToMySQL("pirateWall")
    query = "INSERT INTO messages (message, senders_id, recepient_id, created_at) VALUES (%(message)s, %(senders_id)s, %(recepient_id)s, NOW();"
    data = {
        "message": request.form['message'],
        "senders_id": user_info['id'],
        "recepient_id": request.form["recepient_id"]
    }
    new_message_id=mysql.query_db(query,data)
    return redirect("/wall") 

@app.route("/destroy/<message_id>", methods=['POST'])
def destroymessage():
    mysql = connectToMySQL("pirateWall")
    query ="DELETE FROM messages WHERE id=%(id)s;"
    data ={
        "id": id
    }
    return redirect ('/wall')
if __name__ == "__main__":
    app.run(debug=True)