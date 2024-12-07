from flask import Flask, render_template, request
from forms import *
from scanner import *
import os
from extensions import *
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zap_data_base.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

#Iniciamos SQLAlchemy
db.init_app(app)
migrate = Migrate(app,db)
from models import *



@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    form = ScanForm()
    if form.validate_on_submit():
        url = form.url.data
        strength = form.strength.data
        zap = connection_to_zap()
        is_in_sites(zap, url)
        active_scan(zap,url,strength)
    return render_template('index.html', form=form)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    return render_template('scan.html')
    
if __name__ == '__main__':
    app.run(debug=True)