$(document).ready(function() {
    // Cuando el formulario se envía
    $('#vulnerabiliesForm').on('submit', function(event) {
        // Aquí solo evitamos el envío para AJAX, pero permitimos el comportamiento tradicional (recarga de la página)
        var url = $('#scanUrl').val();  // Asumiendo que el ID del campo es 'scanUrl'

        // Construir los datos a enviar
        var formData = {
            'url': url
        };

        // Hacer la solicitud AJAX
        $.ajax({
            url: '/obtener_comparativa_vulnerabilidades',  // La ruta Flask que manejará la consulta
            type: 'POST',  // Método de la solicitud
            data: formData,  // Los datos del formulario
            success: function(response) {
                // Si la solicitud es exitosa, procesamos la respuesta
                console.log(response);  // Puedes ver la respuesta en la consola

                // Actualiza la interfaz con la respuesta del modelo
                // Supongamos que la respuesta contiene la comparativa de vulnerabilidades
                $('#comparativaVulnerabilidades').text(response.comparativa);  // Muestra la respuesta en el div
            },
            error: function(xhr, status, error) {
                // Manejo de errores si la solicitud falla
                console.error('Error en la solicitud:', error);
            }
        });

        // No usamos event.preventDefault() aquí, para que el formulario se pueda enviar y la página se recargue
    });
});
