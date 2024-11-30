from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, InputRequired, Email
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField

class ScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    strength = SelectField('Strength', choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('INSANE', 'Insane'), ('DEFAULT', 'Default')], validators=[InputRequired()])
    submit = SubmitField('Start Scan')