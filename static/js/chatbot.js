$(document).ready(function () {
    
    $('#send-button').on('click', sendMessage);

    // Manejo de eventos para presionar "Enter" en el campo de entrada
    $('#user-input').on('keypress', function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            sendMessage();
        }
    });

    // Función para enviar el mensaje
    function sendMessage() {
        const userInput = $('#user-input').val().trim();
        if (!userInput) return; // No enviar mensajes vacíos

        const messagesDiv = $('#messages');

        // Escapar el contenido del mensaje del usuario para evitar inyecciones de HTML
        const escapedUserInput = $('<div>').text(userInput).html();

        // Mostrar el mensaje del usuario en la interfaz
        messagesDiv.append(`
            <div class="text-end mb-3">
                <span class="badge bg-primary">${escapedUserInput}</span>
            </div>
        `);
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);

        // Enviar petición AJAX al backend
        $.ajax({
            url: '/context_chatgpt',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ message: userInput }),
            success: function (response) {
                handleBotResponse(response);
            },
            error: function (xhr, status, error) {
                console.error("Error en la petición AJAX:", error);
                displayErrorMessage("Hubo un error al procesar tu mensaje. Por favor, intenta nuevamente.");
            }
        });

        // Limpiar el campo de entrada del usuario
        $('#user-input').val('');
    }

    // Función para manejar la respuesta del bot
    function handleBotResponse(response) {
        const messagesDiv = $('#messages');

        if (!response || !response.reply) {
            console.error("El servidor no devolvió una respuesta válida.");
            displayErrorMessage("El servidor no devolvió una respuesta válida.");
            return;
        }

        const converter = new showdown.Converter();
        const sanitizedReply = $('<div>').text(response.reply).html(); // Escapar contenido
        const html = converter.makeHtml(sanitizedReply);

        const botReply = `
            <div class="text-start mb-3">
                <span class="badge bg-secondary text-wrap">${html}</span>
            </div>
        `;

        // Insertar en el DOM
        messagesDiv.append(botReply);
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);
    }

    // Función para mostrar mensajes de error en la interfaz
    function displayErrorMessage(message) {
        const messagesDiv = $('#messages');
        const errorMessage = `
            <div class="text-start mb-3">
                <span class="badge bg-danger text-wrap">${message}</span>
            </div>
        `;
        messagesDiv.append(errorMessage);
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);
    }
});