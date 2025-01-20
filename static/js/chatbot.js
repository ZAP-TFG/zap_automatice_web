$(document).ready(function () {
    // Al hacer clic en el botón de enviar
    $('#send-button').click(function () {
        sendMessage();
    });

    // Al presionar "Enter" en el input
    $('#user-input').keypress(function (event) {
        if (event.key === "Enter") {
            sendMessage();
        }
    });

    function sendMessage() {
        const userInput = $('#user-input').val().trim();
        if (!userInput) return; // Si no hay input, no hace nada

        const messagesDiv = $('#messages');

        // Mostrar el mensaje del usuario
        const userMessage = `<div class="text-end mb-3">
            <span class="badge bg-primary text-wrap">${userInput}</span>
        </div>`;
        messagesDiv.append(userMessage);
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);

        // Llamada al primer endpoint para obtener el contexto
        $.ajax({
            url: '/context_chatgpt',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ message: userInput }),
            success: function (response) {
                console.log("Respuesta de /context_chatgpt:", response);
                const context = JSON.parse(response.reply); // Asumimos que es JSON

                // Enviar el contexto al segundo endpoint
                sendContextBasedRequest(context, messagesDiv);
            },
            error: function (xhr, status, error) {
                console.error("Error al obtener el contexto:", error);
            }
        });

        // Limpiar el campo de texto
        $('#user-input').val('');
    }

    function sendContextBasedRequest(context, messagesDiv) {
        $.ajax({
            url: '/respuesta_chatgpt', 
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(context), 
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
                messagesDiv.scrollTop(messagesDiv[0].scrollHeight);
            },
            error: function (error) {
                console.error("Error al obtener la respuesta según el contexto:", error);
            }
        });
    }
});
