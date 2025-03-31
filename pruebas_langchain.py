from typing import Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver 
from langchain_google_genai import ChatGoogleGenerativeAI 
from datetime import datetime
from dotenv import load_dotenv
from langchain.tools import tool  # Decorador para herramientas
import os
from extensions import *
#from app import app, db
from models import Escaneo_programados
from google import genai
from sqlalchemy import text
from langchain_core.messages.tool import ToolMessage
# Cargar la clave API desde .env
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=api_key)

"""Definimos el estado de la conversación, una estructura que comparten los nodos
para almacenar los mensajes de la conversación."""
class State(TypedDict):
    messages: Annotated[list, add_messages]

"""Inicializa el gráfico de estado basado en la clase State y será la base para conectar nodos."""
graph_builder = StateGraph(State) # actua como cadena de monataje que partiendo del state inicial añade nuevos inputs y llama a funciones correspondientes

def comparar_reportes(user_input, report_str):
    prompt_text = f"""
        Eres un asistente especializado ciberseguridad y vulnerabilidades. Te van a pasar uno  o dos reportes. Tendras que valorarlo en base a la pregunta del usuario.
        En caso de que te digan resumen sera un solo reporte y en caso de que te pidan comparacion pues se te pasará mas de un reporte.
        El formate de salida siene que ser no demasido largo. No tendras que incluir las vulnerabilidades informativas y podras especificar que alertas crees que son falsos positivos en base a tus conocimeinto.
        Tendras que incluir el resumen, los falsos positivos si los hay y recomendaciones. El formato de salida será en formato markdown.
        La pregunta proporcionada por el usuario es: {user_input}
        reportes: {report_str}
        """
        

    client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt_text
    )

    result = response.text.strip()  
    resumen = str(result)
    return resumen
# Funciones para herramientas decoradas con @tool
@tool
def vulnerabilidades(user_input: str) -> str:
    """Consulta en la base de datos alguna vulnerabilidad concreta sobre las URLS segun la pregunta del usuario.
    Args:
        text (str): La pregunta completa proporcionada por el usuario sobre vulnerabilidades.

    Returns:
        str: Los resultados de la consulta SQL ejecutada en la base de datos."""

    prompt_text = f"""
    Eres un asistente especializado en consultas SQL. Te voy a pasar los atributos del modelo de la tabla y vas a tener que responder con el formato string solo la consulta sin COMILLAS. 
    A MODO DE EJEMPLOE TE ENSEÑO DOS CONSULTAS: 
            SELECT * FROM reportes_vulnerabilidades_url WHERE vul_altas LIKE '%XSS%' OR vul_medias LIKE '%XSS%' OR vul_bajas LIKE '%XSS%' OR vul_info LIKE '%XSS%';
            SELECT (COALESCE(JSON_ARRAY_LENGTH(vul_altas), 0) + COALESCE(JSON_ARRAY_LENGTH(vul_medias), 0) + COALESCE(JSON_ARRAY_LENGTH(vul_bajas), 0) + COALESCE(JSON_ARRAY_LENGTH(vul_info), 0)) AS total_vulnerabilidades FROM tu_tabla WHERE url = 'url_especifica' ORDER BY fecha_scan DESC LIMIT 1;
    No puedes incluir  nunca el report_file cuando re preguntan por vulnerabilidades.
    En caso de que te preguntes por una url concreta tendras que sacar la ultima añadida a la tabla. 

    class Escaneo_programados(db.Model):
        __tablename__ = 'reportes_vulnerabilidades_url'  

        id 
        target_url 
        vul_altas = db.Column(JSON, nullable=True)
        vul_medias = db.Column(JSON, nullable=True)
        vul_bajas = db.Column(JSON, nullable=True)
        vul_info = db.Column(JSON, nullable=True)
        fecha_scan = db.Column(db.DateTime, default=datetime.now(timezone.utc)) 
        report_file = db.Column(JSON, nullable=True)

    La pregunta proporcionada por el usuario es: {user_input}
    """
    
    # Llamar al modelo Gemini para generar la consulta SQL
    client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt_text
    )

    query = response.text.strip()  
    print(f"Consulta generada: {query}")
    result = db.session.execute(text(query)).fetchall()
    result = str(result)

    return result
    

@tool
def consultar_escaneres_programados(input: str) -> str:
    """
    Consulta los escaneos programados en la base de datos según la pregunta del usuario.

    Args:
        text (str): La pregunta proporcionada por el usuario sobre los escaneos programados.

    Returns:
        str: Los resultados de la consulta SQL ejecutada en la base de datos.
    """

    date = datetime.now().strftime('%Y-%m-%dT%H:%M')
    
    # Crear el prompt para el modelo
    prompt_text = f"""
    Eres un asistente especializado en consultas SQL. Te voy a pasar los atributos del modelo de la tabla y vas a tener que responder con el formato string solo la consulta sin COMILLAS. 
    El día de hoy es: {date}.
    Para poder filtrar por fecha debes hacer la consulta con el mismo formato de fecha '%Y-%m-%d%', además tendrás que ver si el estado está pendiente o no.
    Ten en cuenta que la fecha aparece con dia y hora si no te dicen hora tendras que sacar todos los escaneres programados para ese dia.
    class Escaneo_programados(db.Model):
        __tablename__ = 'escaneos_programados'
        id  
        target_url  
        intensidad  
        fecha_programada = (dateTime, '%Y-%m-%dT%H:%M')
        estado = db.Column(db.String(50), nullable=False, default='PENDIENTE') 
        archivo_subido 
        api_scan 
        api_file 
        periodicidad_dias 

    La pregunta proporcionada por el usuario es: {input}
    """
    
    # Llamar al modelo Gemini para generar la consulta SQL
    client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt_text
    )

    query = response.text.strip()  
    print(f"Consulta generada: {query}")
    result = db.session.execute(text(query)).fetchall()
    result = str(result)
        
    return result

@tool
def resumenes_comparacion(user_input: str) -> str:
    """
    resume o compara los reportes de una URL según la pregunta del usuario
    Args:
        text (str): La pregunta proporcionada por el usuario sobre comparacion o resumenes de reportes.

    Returns:
        str: Los resultados del resumen o la comparacion entre reportes.
    """
    
    
    prompt_text = f"""
        Eres un asistente especializado en consultas SQL. Te voy a pasar un ejemplo de como tiene que ser la consulta y la estructura de mi tabla y vas a tener que responder con el formato string solo la consulta sin COMILLAS. 
        Ejemplo:   
            SELECT report_file FROM reportes_vulnerabilidades_url WHERE target_url='https://example.com/' ORDER BY fecha_scan DESC LIMIT 1
        Estrcutura tabla:
            target_url 
            report_file = db.Column(JSON, nullable=True)
        El usuairo re podra pedir tanto resumenes como comparaciones, tendras que ejecutar la consulta en base a lo que te pidan.
        La pregunta proporcionada por el usuario es: {user_input}
        """
    

    client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt_text
    )

    query = response.text.strip()  
    print(f"Consulta generada: {query}")
    result = db.session.execute(text(query)).fetchall()
    result = str(result)
    resumen = comparar_reportes(user_input, result)
    return resumen

@tool
def consultar_escaneres_ejecutandose(input: str) -> str:
    """
    Consulta los escaneos que se estan ejecutando actualmente en la base de datos según la pregunta del usuario.

    Args:
        text (str): La pregunta proporcionada por el usuario sobre los escaneos programados.

    Returns:
        str: Los resultados de la consulta SQL ejecutada en la base de datos.
    """

    date = datetime.now().strftime('%Y-%m-%dT%H:%M')
    
    # Crear el prompt para el modelo
    prompt_text = f"""
    Eres un asistente especializado en consultas SQL. Te voy a pasar los atributos del modelo de la tabla y vas a tener que responder con el formato string solo la consulta sin COMILLAS. 
    El día de hoy es: {date}.
    Para poder filtrar por fecha debes hacer la consulta con el mismo formato de fecha '%Y-%m-%d%', además tendrás que ver si el estado está pendiente o no.
    Ten en cuenta que la fecha aparece con dia y hora si no te dicen hora tendras que sacar todos los escaneres programados para ese dia.
    class Escaneres_completados(db.Model):
    __tablename__ = 'escaneos_completados'  

        id = 
        target_url = db.Column(db.String(200), nullable=False, index=True)
        estado = db.Column(db.String(50), nullable=False, default='En proceso')
        fecha_inicio = db.Column(db.DateTime(timezone=True), default=get_utc_now)
        fecha_fin = db.Column(db.DateTime(timezone=True), default=get_utc_now)
        intensidad 

    __table_args__ = (
        Index('idx_target_url_estado', 'target_url', 'estado'),
    )
    La pregunta proporcionada por el usuario es: {input}
    """
    
    # Llamar al modelo Gemini para generar la consulta SQL
    client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt_text
    )

    query = response.text.strip()  
    print(f"Consulta generada: {query}")
    result = db.session.execute(text(query)).fetchall()
    result = str(result)
        
    return result


# Lista de herramientas disponibles
tools = [vulnerabilidades, consultar_escaneres_programados, resumenes_comparacion, consultar_escaneres_ejecutandose]

# Vincular las herramientas al modelo Gemini
llm_with_tools = llm.bind_tools(tools)

"""Función principal del chatbot encargada de procesar el estado actual de la conversación
y devolver una respuesta utilizando el modelo de lenguaje."""
def chatbot(state: State):
    return {"messages": [llm_with_tools.invoke(state["messages"])]}

def tool_redirect_condition(state: State):
    """Si la tool ejecutada es 'resumenes', va directo al usuario sin pasar por el chatbot."""
    last_message = state["messages"][-1]

    if isinstance(last_message, ToolMessage) and last_message.name == "resumenes_comparacion":
        return "output"  # Salida directa al usuario
    return "chatbot" 

# Añadir nodos al gráfico
graph_builder.add_node("chatbot", chatbot)

# Crear un nodo para las herramientas
tools_node = ToolNode(tools=tools)
graph_builder.add_node("tools", tools_node)

def output_direct(state: State):
    """Este nodo simplemente devuelve el mensaje generado por la tool sin modificarlo."""
    return state["messages"][-1]

graph_builder.add_node("output", output_direct)

"""Define una conexión condicional entre el nodo chatbot y las herramientas.
tools_condition es una condición predefinida que verifica si debe usar las tools o no 
en base al mensaje del usuario."""
graph_builder.add_conditional_edges(
    "chatbot",
    tools_condition,
)

graph_builder.add_conditional_edges(
   "tools",
    tool_redirect_condition,
)
"""Esto especifica que si pasa por tools tiene que volver a chatbot y que empieza por chatbot."""
#graph_builder.add_edge("output", "chatbot")
graph_builder.add_edge(START, "chatbot")

"""Añadimos memoria para tener continuidad en la conversación.
compile(checkpointer=memory) compila el gráfico utilizando MemorySaver, lo que asegura 
que el chatbot pueda recordar todos los mensajes."""
memory = MemorySaver()
graph_memory = graph_builder.compile(checkpointer=memory) #checkpoint es el componente encargado de guardar la conversacion

"""Ahora corremos el código.
Definimos el diccionario configuración en que decimos que queremos tener un único hilo de conversación."""
config = {"configurable": {"thread_id": "1"}}

"""
while True:
    user_input = input("User: ")
    if user_input.lower() in ["quit", "q"]:
        print("Goodbye!")
        break
    events = graph_memory.stream(
        {"messages": [("user", user_input)]}, config, stream_mode="values"
    )
    for event in events:
        event["messages"][-1].pretty_print()"""
