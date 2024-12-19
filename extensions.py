from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.sqlite import JSON
from flask import Flask, render_template, request, jsonify

db = SQLAlchemy()

app = Flask(__name__)