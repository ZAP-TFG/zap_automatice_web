from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, InputRequired, Email, Optional, ValidationError, URL
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, DateTimeLocalField, FileField


class ScanForm(FlaskForm):

    url = StringField('Target URL', validators=[DataRequired()], render_kw={"placeholder": "https://example.com"})
    strength = SelectField(' Set Strength', choices=[ ('DEFAULT', 'Default'), ('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('INSANE', 'Insane')], validators=[InputRequired()])
    schedule = BooleanField('Schedule', default=False)
    scanDateTime = DateTimeLocalField("Select Date & Time", format='%d/%m/%Y %H:%M', validators=[Optional()], render_kw={"class": "form-control"})
    apiscan = BooleanField('API Scan', default=False)
    configFile = FileField('Upload API File', validators=[Optional()])  
    email = StringField('Email to send', validators=[DataRequired()])
    submit = SubmitField('Start Scan')

    def validate_scanDateTime(self, field):
        if self.schedule.data and not field.data:
            raise ValidationError('Date and Time is required if you are scheduling the scan.')


class ChatForm(FlaskForm):
    message = StringField('User Message', validators=[DataRequired()], render_kw={"placeholder": "Escribe mensage aqui"})
    submit = SubmitField('Enviar')
    submit2 = SubmitField('Configuracion')


def file_type_check(form, field):
    if not field.data.filename.endswith('.json'):
        raise ValidationError("Solo se permiten archivos JSON.")

class FileUploadForm(FlaskForm):
    file = FileField('Subir archivo JSON', validators=[
        DataRequired(message="Debe seleccionar un archivo."),
        file_type_check
    ])
    submit = SubmitField('Procesar archivo')