from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import pandas as pd
from datetime import timedelta


# Generate a random 24-byte (48-character) hexadecimal string
secret_key = secrets.token_hex(32)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.secret_key = secret_key  
ADMIN = 'admin'
TEACHER = 'teacher'
STUDENT = 'student'


db = SQLAlchemy(app)

# Define User, Class, Student, and Attendance models here
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=True)
    email = db.Column(db.String(20), unique=True, nullable=False)
    student = db.Column(db.Boolean)
    lecture = db.Column(db.Boolean)
    password = db.Column(db.String(120), nullable=False)

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_code = db.Column(db.String(10), unique=True, nullable=False)
    class_name = db.Column(db.String(80), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    adm_no = db.Column(db.String(10), unique=True, nullable=False)
    

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    student = db.relationship('Student', backref=db.backref('attendance', lazy=True))



# User authentication functions

def login_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        print(session['user_id'])
        print(user.role)
        return user.role  # Return the user's role after successful login
    return None



def logout_user():
    session.pop('user_id', None)

def is_logged_in():
    print('user_id' in session)
    return 'user_id' in session


# Views
def get_user_role():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            return user.role
    return None




@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']  # This will be 'admin'

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Admin registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('admin_register.html')




@app.route('/admin_dashboard')
def admin_dashboard():
    print(f'Session Content: {session}')
    if is_logged_in() and get_user_role() == ADMIN:
        print(is_logged_in())
        print(get_user_role())
        return render_template('admin_dashboard.html')
    else:
        return redirect(url_for('login'))
    
@app.route('/teacher_dashboard')
def teacher_dashboard():
    print(f'Session Content: {session}')
    if is_logged_in() and get_user_role() == TEACHER:
        print(is_logged_in())
        print(get_user_role())
        return render_template('teacher_dashboard.html')
    else:
        return redirect(url_for('login'))

@app.route('/student_dashboard')
def student_dashboard():
    print(f'Session Content: {session}')
    if is_logged_in() and get_user_role() == STUDENT:
        print(is_logged_in())
        print(get_user_role())
        return render_template('student_dashboard.html')
    else:
        return redirect(url_for('login'))

@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        role = login_user(email, password)
        print(role)

        if role:
            if role == STUDENT:
                return redirect(url_for('student_dashboard'))
            elif role == TEACHER:
                return redirect(url_for('teacher_dashboard'))
            elif role == ADMIN:
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        position = request.form['position']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='sha256')

        if position == 'student':
            role = STUDENT
        elif position == 'teacher':
            role = TEACHER
        elif position == 'admin':
            role = ADMIN
        else:
            role = None

        if role:
            # Check if the email already exists
            existing_user = User.query.filter_by(email=email).first()

            if existing_user:
                flash('Email already exists. Please use a different email.', 'danger')
                return redirect(url_for('register'))

            new_user = User(username=username, email=email, role=role, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid user role. Please try again.', 'danger')

    return render_template('register.html')



@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', is_logged_in=is_logged_in())

@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


# ... (previous code)

# ... (User authentication functions and Views)

# Add the following Class and Student management views

@app.route('/class_list', methods=['GET','POST'])
def class_list():
    if is_logged_in():
        classes = Class.query.all()
        items = User.query.all()
        attend = Attendance.query.all()
        classes = Class.query.all()
        print(attend)
        reg_students = Student.query.all()

        return render_template('class_list.html', classes=classes, items=items,attend=attend,reg_students=reg_students)
    return redirect(url_for('login'))

@app.route('/student', methods=['GET','POST'])
def student():
    if is_logged_in():
        if request.method == 'POST':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            Adm_no = request.form['Adm_no']
            new_std = Student(first_name=first_name,last_name=last_name,email=email,adm_no=Adm_no,class_id=2)
            # print(new_std)
            db.session.add(new_std)
            db.session.commit()
            reg_students = Student.query.all()
            # students = Student.query.filter_by(class_id=class_id).all()
            
            return render_template('students.html', reg_students=reg_students)
    return render_template('students.html')

# id = db.Column(db.Integer, primary_key=True)
#     first_name = db.Column(db.String(80), nullable=False)
#     last_name = db.Column(db.String(80), nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     adm_no = db.Column(db.String(10), unique=True, nullable=False)
#     class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
#     _class = db.relationship('Class', backref=db.backref('students', lazy=True))
# ... (previous code)

# ... (Class and Student management views)

# Add the following Attendance management views

# @app.route('/take_attendance')
# def take_attendance():
#     if is_logged_in():
#         if request.method == 'POST':
#             student_id = Student.id
#             date =  datetime.utcnow().date()
#             status = "present"
#             new_attendance = Attendance(student_id=student_id,date=date,status=status)
#             db.session.add(new_attendance)
#             db.session.commit()
#             flash('Registration successful! Please log in.', 'success')
#             return redirect(url_for('attendance'))
#     return redirect(url_for('attendance'))

# @app.route('/submit_attendance', methods=['GET','POST'])
# def submit_attendance():
#     if is_logged_in():
#         status = request.form['status']

#         new_attendance = Attendance(status=status)
#         db.session.add(new_attendance)
#         db.session.commit()

#         return redirect(url_for('submit_attendance'))
#     return redirect(url_for('login'))

@app.route('/attendance', methods=['GET', 'POST'])
def attendance():
    if request.method == 'POST':
        requested_adm_no = request.form['adm_no']
        person_id = Student.query.filter_by(adm_no=requested_adm_no).first()
        print(person_id.email)
        if person_id == None:
            print('empty adm')
        else:
            student_id = requested_adm_no
            print(student_id)
        
        email = request.form['email']
        user_email = person_id.email
        date =  datetime.utcnow().date()
        status = request.form['status']
        if user_email == email:
            print("<---------------------------------------attendance taken!!!!-------------------------------->")
            new_attendance = Attendance(student_id=student_id,date=date,status=status) 
            print(new_attendance.date )
            db.session.add(new_attendance)
            db.session.commit()
            return redirect(url_for('dashboard'))
    return render_template('attendance.html')



@app.route('/register_classes', methods=['GET', 'POST'])
def register_classes():
    if request.method == 'POST':
        class_code = request.form['class_code']
        class_name = request.form['class_name']

        new_class = Class(class_code=class_code, class_name=class_name)
        db.session.add(new_class)
        db.session.commit()

        flash('Registration successful!', 'success')

    return render_template('register_classes.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        if file and file.filename.endswith(('.csv', '.xlsx')):
            df = pd.read_excel(file)
            for _, row in df.iterrows():
                username = row['Username']
                password = row['Password']
                new_user = User(username=username, password=password)
                db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))

    return render_template('upload.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if is_logged_in():
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            
            # Get the current user
            user_id = session['user_id']
            user = User.query.get(user_id)
            
            # Check if the entered current password is correct
            if check_password_hash(user.password, current_password):
                # Check if the new password and confirmation match
                if new_password == confirm_new_password:
                    # Update the user's password
                    user.password = generate_password_hash(new_password, method='sha256')
                    db.session.commit()
                    flash('Password changed successfully!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('New passwords do not match. Please try again.', 'danger')
            else:
                flash('Invalid current password. Please try again.', 'danger')

        return render_template('change_password.html')
    return redirect(url_for('login'))






if __name__ == '__main__':
    # db.create_all()
    app.run(debug=True)