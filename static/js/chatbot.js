$(document).ready(function () {
    
    $('#send-button').click(function () {
        sendMessage();
    });

    $('#user-input').keypress(function (event) {
        if (event.key === "Enter") {
            event.preventDefault(); 
            sendMessage();
        }
    });

    function sendMessage() {
        const userInput = $('#user-input').val().trim();
        if (!userInput) return; 

        const messagesDiv = $('#messages');

        // Muestra el mensaje del usuario en la interfaz
        messagesDiv.append(`<div class="text-end mb-3"><span class="badge bg-primary">${userInput}</span></div>`);
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);

        // Enviar petición AJAX al backend
        $.ajax({
            url: '/context_chatgpt',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ message: userInput }),
            success: function (response) {
                console.log("Response:",response.reply);
                if (!response.reply) {
                    console.error("El servidor no devolvió una respuesta válida.");
                    return;
                }
                var convert = new showdown.Converter();
                var html = convert.makeHtml(response.reply || "Error en el servidor.")
                console.log("HTML Content generado:", html);

                // Construir el mensaje del bot
                const botReply = `<div class="text-start mb-3">
                    <span class="badge bg-secondary text-wrap">${html}</span>
                </div>`;

                // Insertar en el DOM
                messagesDiv.append(botReply);
                messagesDiv.scrollTop(messagesDiv[0].scrollHeight)
            },
            error: function (xhr, status, error) {
                console.error("Error en la petición AJAX:", error);
            }
        });

        // Limpiar input del usuario
        $('#user-input').val('');
    }

    function formatReply(reply) {
        return reply.replace(/\n/g, '<br>'); // Reemplazar \n con etiquetas <br> para mostrar saltos de línea en HTML
    }
});
