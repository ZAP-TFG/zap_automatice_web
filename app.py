from flask import Flask, render_template, request
from forms import *
from scanner import *
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)

@app.route('/', methods=['GET', 'POST'])
def home():
    form = ScanForm()
    if form.validate_on_submit():
        url = form.url.data
        strength = form.strength.data
        zap = connection_to_zap()
        is_in_sites(zap, url)
        active_scan(zap,url,strength)
    return render_template('index.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)