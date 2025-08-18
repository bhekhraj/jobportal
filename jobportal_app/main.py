from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import PrimaryKeyConstraint
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(50))  # 'admin', 'employer', 'user'



# Job model
class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    company = db.Column(db.String(100))
    salary = db.Column(db.String(100))
    #location = db.Column(db.String(100))
    posted_by = db.Column(db.Integer, db.ForeignKey('user.id'))

#register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        user = User()
        user.username=username
        user.password=password
        user.role=role
        db.session.add(user)
        db.session.commit()
        return "registration successfull"
    return render_template('register.html')

#kogin route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            if user.role =='admin':
                session['role']='admin'
                session['user_id']=user.id
                return redirect('/admin')
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
        else:
            return"invalid username or password"
        return redirect('/dashboard')
    return render_template('login.html')

#dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    role = session['role']
    if role == 'admin':
        users = User.query.all()
        jobs = Job.query.all()
        return render_template('admin.html', users=users, jobs=jobs)
    elif role == 'employer':
        jobs = Job.query.filter_by(posted_by=session['user_id']).all()
        user = User.query.filter_by(id=session['user_id']).first()
        return render_template('dashboard.html', user=user, jobs=jobs, role=role)
    else:
        jobs = Job.query.all()
        user = User.query.filter_by(id=session['user_id']).first()
        return render_template('dashboard.html', user=user, jobs=jobs, role=role)
        
#post-jobs route
@app.route('/post-job', methods=['GET', 'POST'])
def post_job():
    if session.get('role') not in ['admin', 'employer']:
        return "Unauthorized! please login first"
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            job = Job()
            job.title = request.form['title']
            job.description = request.form['description']
            job.company = request.form['company']
            job.salary = request.form.get('salary', '')
            job.posted_by = session['user_id']
            if job.title and job.description and job.company:
                db.session.add(job)
                db.session.commit()
        elif action == 'remove':
            job_id = request.form['job_id']
            job = Job.query.filter_by(id=job_id).first()
            if job:
                db.session.delete(job)
                db.session.commit()
        return redirect('/post_job')
    return render_template('post_job.html')

#admin-creation
def create_admin(username,password):
    #if session.get('role') !='admin':
       # return "only admin can access this page"
    with app.app_context():
        # Check if admin already exists
        existing_admin = User.query.filter_by(username=username).first()
        if existing_admin:
            print("Admin user already exists.")
            return
        # Hash the password
        password = generate_password_hash(password)

        # Create new admin user
        admin_user = User()
        admin_user.id = (PrimaryKeyConstraint)
        admin_user.username=username
        admin_user.password=password
        admin_user.role='admin'
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{username}' created successfully.")

# creating admin user
#create_admin('admin', 'admin@123')

#manage-user route
@app.route('/manage-user', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' not in session:
        return redirect('/login')
    
    role = session.get('role')
    
    if role != 'admin':
        return "Only admins can access this page"
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            username = request.form['username']
            password = generate_password_hash(request.form['password'])
            user_role = request.form['role']
            
            if username and password and user_role:
                user = User()
                user.username = username
                user.password = password
                user.role = user_role
                db.session.add(user)
                db.session.commit()
                return redirect('/admin')
        
        elif action == 'remove':
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            
            if user:
                db.session.delete(user)
                db.session.commit()
                return redirect('/admin')
    
    return render_template('manage_users.html')
#admin route            
@app.route('/admin')
def admin():
    if session.get('role') == 'admin':
        users = User.query.all()
        return render_template('admin.html', users=users)
    return 'only admin can access this page'

           

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/apply/<int:id>')
def apply(id):
    job=Job.query.filter_by(id=id).first()
    if job:
        return render_template('applyform.html')
    return render_template('index.html', job=job)
    
    
    

@app.route('/')
def index():
    jobs = Job.query.all()
    search = request.args.get('search')
    if search:
       search_res = Job.query.filter(Job.title.contains(search) | Job.description.contains(search)).all()
       return render_template('index.html', jobs=jobs,search_res=search_res)
    filter1= request.args.get('job_title')
    filter2= request.args.get('company')
    filter3= request.args.get('location')
    if filter1:
        f_jobs = Job.query.filter_by(title=filter1).all()
        return render_template('index.html', f_jobs=f_jobs)
    elif filter2:
        f_jobs = Job.query.filter_by(company=filter2).all()
        return render_template('index.html', f_jobs=f_jobs)
    elif filter3:
        f_jobs = Job.query.filter_by(location=filter3).all()
        return render_template('index.html', f_jobs=f_jobs)
    return render_template('index.html', jobs=jobs)
    

if __name__ == '__main__':
   
    with app.app_context():
        db.create_all()
        
    app.run(host='0.0.0.0', port=5000, debug=True)
