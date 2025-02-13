from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC

"""
Scikit-learn es una biblioteca de Python de código abierto para machine learning, que ofrece herramientas simples y 
eficientes para análisis predictivo, incluyendo algoritmos de clasificación, regresión, clustering y preprocesamiento de datos. Se basa en NumPy, SciPy y Matplotlib.

TfidfVectorizer: Convierte texto en números para que el modelo lo entienda
SVC: Es un modelo de Machine Learning que clasifica texto en diferentes categorías

"""
"""
En machine learning cuando se entrena a un modela se necesitan ejemplos para que el algoritmo sepa reconocer patrones
x_train -> son frases o textos que el usuario puede decir
y_train -> es la categoria a la que pertenece cada frase
"""

"""
La idea de este codigo es convertir el texto en vectores numericos usando TF-IDF y entrenando un modelo SVM.
1. Creamos un modelo TfidVecotorizer texto-> numeros
2. vectorizer.fit_trasnforme(x_train) -> fit es que aprende y trasform trasnforma las frases en un vecotr numero( en concreto una matriz donde cada palabra tiene su peso segun importancia)
        Palabra	Quiero	un	escaneo	Programa	de	alta	intensidad	Resumen	del	último
    Frase 1 (1)	0.5	    0.3	  0.8	 0.0	    0.0	 0.0	    0.0	      0.0	0.0	  0.0
    Frase 2 (2)	0.0	    0.2	  0.5	 0.7	    0.3	 0.4	     0.5	  0.0	0.0	  0.0
    Frase 3 (3)	0.0	    0.0	  0.6	 0.0	    0.0	 0.0	    0.0	      0.5	0.6	  0.8
3. clf = SVC() -> creamos un modelo SVM(Support Vector Machine)
    clf.fit(xtrain_vectors, y_train)-> entrena al modelo usado los vectores TF-IDF
                                        y aprende de cada palabra que esta asociada a y_train
4. Trasformamos las frases de prueba con vectorizer
    X_test_vectors = vectorizer.transform(test_phrases)
5. Precide las categorias una a una con las frases dadas de test
    predictions = clf.predict(X_test_vectors)

                                        
"""
x_train = [
    # CONFIGURACION
    "Configurame un escaner para https://example.com con intesidad media para mañana a las 12",
    "Programame un escaner para https://example.com con intesidad baja para el 14 de diciembre de 2025",
    "Lanzame un escaner para http://example.com con intesidad media para ahora",
    "Inicia un escaneo para https://sub.example.com con intensidad alta hoy a las 18:30",
    "Ejecuta un escáner en http://test.example.org:8080 con nivel bajo el 05/07/2024 a las 08:00",
    "Prepara un escaneo para https://example.es intensidad media pasado mañana al mediodía",
    "Lanza un escáner en https://api.example.com intensidad media el primer lunes de enero",
    "Hazme un escaner pa hxxp://exampel.com con intenciad alta ora mismo",
    "Quiero un escaneo urgente en example.com nivel máximo ya",
    "Necesito un escaneo para https://example.com ¿puedes hacerlo?",
    "Escanea la IP 192.0.2.1 con intensidad media el viernes a las 16:00",
    "Lanza escáner en example.com/path?param=1 nivel bajo en 30 minutos",

    # RESUMENES
    "Resumeme el ultimo informe de https://example.com",
    "resumeme el ultimo escaner realizado",
    "Genera un resumen del informe más reciente de https://docs.example.net",
    "Hazme un resúmen del último análisis de http://audit.cosas.org",
    "Dame un resumen ejecutivo del escaneo de 192.168.0.1 de ayer",
    "Resume el escaneo de example.com/path del mes pasado",
    "Resiume el ultimo informe de hxxps://exampel.com",
    "Resumen del último escaner de example.com pa hoy",
    "https://example.com resumeme su ultimo informe",
    "consulta el ultimo resumen de esta url: http://gabreiel.es",

    # HISTORIAL
    "Que hay de nuevo respecto ayer",
    "Algon escaner ejecutandose?",
    "Programacion de escaneres para hoy?",
    "cuantos escaneres hemos ejecutado en esta semana?",
    "Quiero ver los últimos reportes generados",
    "Que escaneos hay progrmados para mañana?",
    "Verifica si hay escaneos activos en este momento",
    "¿Cuántos escaneos se lanzaron entre el lunes y hoy?",
    "Escaneos en progreso alrededor de las 15:00",
    "¿Qué escaneos están pendientes para el viernes?",
    "q escaneos hay ahora? avísame" ,
    "cuantos escaneres hicimos sta semana",
    "¿Hay algo nuevo?",
    "Escaneos ejecutados en 192.168.1.0/24 entre el 01-01-2024 y 15-01-2024",
    "Confirmame que escaneos se estan ejecutando",

    # COMPARACION
    "Analiza las diferencias entre los últimos 3 reportes de https://api.example.com",
    "Contrasta el informe de http://test.example.org de ayer con el de hoy",
    "¿En qué se diferencian los reportes más recientes de ftp://files.example.net?",
    "Compara los reportes de example.com de enero y febrero de 2024", 
    "comparame los dos ultimos reportes de https://example.com",
    "resumeme los ultimos reportes de https://example.com",
    "¿Qué ha cambiado en los reportes de 10.0.0.5 desde mayo hasta ahora?",
    "Contrasta los análisis de example.com sin incluir datos técnicos",
    "Compara todos los reportes históricos de https://archive.example.net",
    "¿Qué cambió entre estos análisis?",
    "Diferencias en los últimos escaneos",
    "Diferencias entre los escaneos de 203.0.113.7 con y sin vulnerabilidades críticas",
    "Contrasta los reportes en bullet points",
    "Contejame los dos ultimos inforemes realizados",

    #VULNERABILDIADES
    "En que url tenemos XSS",
    "Dime las urls que tienen SQLi",
    "en que escaneres hemos encontrado CSRF",
    "cuantas urls tenemos donde tengan vulnerabildades altas",
    "Lista las URLs con vulnerabilidades de inyección SQL",
    "Identifica en qué escaneos se detectó CSRF",
    "¿Qué escaneos encontraron SSRF en los últimos 3 meses?",
    "en q urls ay XSS?? avísame",
    "¿Cuántas vulnerabilidades hay?",
    "Vulnerabilidades de tipo CVE-2024-1234 en 192.168.1.0",
    "Escaneos que detectaron CSRF + IDOR en api.example.com",
    "¿En qué URLs hay XSS y CSRF simultáneamente?",
    "Donde hay falta de anticlick-jacking?",
    "cuantas vulnerabildiades tiene la url http://example.com",
    "Cuantas vulneabilidades criticas tiene la url https://gabriel.es",

    #PREGUNTAS
    "Que es la vulnerabilidad Path traversal",
    "Como solvento la el buffer overflow",
    "porque sse produce SQLi",
    "que dia es hoy?",
    "¿Qué es un XSS almacenado?",
    "Explica cómo funciona un ataque de fuerza bruta",
    "¿Por qué ocurren las vulnerabilidades de desbordamiento de buffer?",
    "¿Qué hora es en Londres ahora?",
    "¿Cómo se explota un IDOR en una API?",
    "¿Qué diferencia hay entre CSRF y Clickjacking?",
    "¿En qué mes estamos?",
    "¿Qué pasaría si hay XSS + CSRF en la misma URL?",
    "¿Es posible un buffer overflow en Python?",
    "¿Qué es un CORS misconfiguration",
    "Explica el CWE-89 con un ejemplo práctico",
    "Como distingo entre XSS reflected y alamcenado?",
    "Que significa XSS",

    #DETALLES
    "Explicame la vulenrabilidad 3 del resumen que me has pasado",
    "Como solvento la SQLi del resumen",
    "Explicame la vulnerabilidad 8 del resumen que me has pasado",
    "¿Cómo soluciono la SQLi que mencionaste en el ID 3?",
    "¿Qué severidad tiene la vulnerabilidad 1 del resumen anterior?",
    "¿En qué consiste la vulnerabilidad 2 del informe que me enviaste?",
    "Dame más detalles sobre el CSRF que aparece en el resumen de ayer",
    "explicame la vulnerabilidad 2",
    "explicame la vuln 3 d ese resumen",
    "como arreglar la SQLi del resumen?",
    "¿Cómo parcheo la vulnerabilidad número 50?",
    "¿Qué pasa si ignoro la vulnerabilidad 25?",
    "¿Qué era eso del CSRF?",
    "¿Qué significa el campo severity: 9 en la vulnerabilidad 2 del JSON?",
    "aclarame lo que significa esto que has dicho: buffer overflow",
    "que es eso que has dicho de XSS"

]

y_train = y_train = ["configuracion"] * 12 + ["resumenes"] * 10 + ["historial"] * 15 + ["comparacion"] * 14 + ["vulnerabilidades"] * 15 + ["preguntas"] * 17 + ["detalles"] * 16

vectorizer = TfidfVectorizer()
X_train_vectors = vectorizer.fit_transform(x_train)

clf = SVC()
clf.fit(X_train_vectors, y_train)

while True:
    frase = input("escribe frase para testear:  ")

    X_test_vectors = vectorizer.transform([frase])

    predictions = clf.predict(X_test_vectors)
    print(f"Frase: {frase} → Categoría: {predictions}")
