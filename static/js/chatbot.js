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
            url: '/respuesta_chatgpt', // Ruta para obtener la respuesta según el contexto
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(context), // Enviamos el JSON completo
            success: function (response) {
                // Mostrar la respuesta final del chatbot
                const botReply = `<div class="text-start mb-3">
                    <span class="badge bg-secondary text-wrap">${response.reply || "Error en el servidor."}</span>
                </div>`;
                messagesDiv.append(botReply);
                messagesDiv.scrollTop(messagesDiv[0].scrollHeight);
            },
            error: function (error) {
                console.error("Error al obtener la respuesta según el contexto:", error);
            }
        });
    }
});
