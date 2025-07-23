$(document).ready(function () {
    
    // Variables globales
    let typingTimeout;
    
    // Event listeners principales
    $('#send-button').on('click', sendMessage);
    $('#send-button-main').on('click', sendMessage);
    $('#clear-chat').on('click', clearChat);
    $('#minimize-chat').on('click', toggleMinimize);
    
    // Manejo de eventos para presionar "Enter"
    $('#user-input').on('keypress', function (event) {
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            sendMessage();
        }
    });
    
    // Auto-resize del textarea y contador de caracteres
    $('#user-input').on('input', function() {
        updateCharacterCount();
        autoResize();
    });
    
    // Función principal para enviar mensajes
    function sendMessage() {
        const userInput = $('#user-input').val().trim();
        if (!userInput) return;
        
        // Agregar mensaje del usuario
        addMessage(userInput, 'user');
        
        // Limpiar input
        $('#user-input').val('');
        updateCharacterCount();
        autoResize();
        
        // Mostrar indicador de escritura
        showTypingIndicator();
        
        // Enviar petición AJAX
        $.ajax({
            url: '/context_chatgpt',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ message: userInput }),
            success: function (response) {
                hideTypingIndicator();
                handleBotResponse(response);
            },
            error: function (xhr, status, error) {
                console.error("Error en la petición AJAX:", error);
                hideTypingIndicator();
                displayErrorMessage("Hubo un error al procesar tu mensaje. Por favor, intenta nuevamente.");
            }
        });
    }
    
    // Función para obtener timestamp actual
    function getCurrentTimestamp() {
        const now = new Date();
        return now.toLocaleTimeString('es-ES', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }
    
    // Función para agregar mensajes con el nuevo diseño
    function addMessage(content, type) {
        const messagesDiv = $('#messages');
        const timestamp = getCurrentTimestamp();
        
        // Escapar contenido para seguridad
        const escapedContent = $('<div>').text(content).html();
        
        let avatarHtml = '';
        if (type === 'user') {
            avatarHtml = '<div class="user-avatar"><i class="fas fa-user"></i></div>';
        } else {
            avatarHtml = '<div class="bot-avatar-small"><i class="fas fa-robot"></i></div>';
        }
        
        const messageHtml = `
            <div class="message ${type}-message">
                <div class="message-avatar">
                    ${avatarHtml}
                </div>
                <div class="message-content">
                    <div class="message-bubble">
                        ${type === 'user' ? escapedContent : content}
                    </div>
                    <div class="message-time">
                        <span class="timestamp">${timestamp}</span>
                    </div>
                </div>
            </div>
        `;
        
        messagesDiv.append(messageHtml);
        scrollToBottom();
    }
    
    // Función para manejar respuesta del bot (adaptada a tu estructura)
    function handleBotResponse(response) {
        if (!response || !response.reply) {
            console.error("El servidor no devolvió una respuesta válida.");
            displayErrorMessage("El servidor no devolvió una respuesta válida.");
            return;
        }
        
        const converter = new showdown.Converter();
        const html = converter.makeHtml(response.reply);
        
        addMessage(html, 'bot');
    }
    
    // Mostrar indicador de escritura
    function showTypingIndicator() {
        $('#typing-indicator').show();
        scrollToBottom();
    }
    
    // Ocultar indicador de escritura
    function hideTypingIndicator() {
        $('#typing-indicator').hide();
    }
    
    // Función para mostrar errores (adaptada a tu estructura)
    function displayErrorMessage(message) {
        const timestamp = getCurrentTimestamp();
        const errorHtml = `
            <div class="message bot-message error-message">
                <div class="message-avatar">
                    <div class="bot-avatar-small"><i class="fas fa-robot"></i></div>
                </div>
                <div class="message-content">
                    <div class="message-bubble error-bubble">
                        <i class="fas fa-exclamation-triangle"></i> ${message}
                    </div>
                    <div class="message-time">
                        <span class="timestamp">${timestamp}</span>
                    </div>
                </div>
            </div>
        `;
        
        $('#messages').append(errorHtml);
        scrollToBottom();
    }
    
    // Funciones auxiliares
    function updateCharacterCount() {
        const count = $('#user-input').val().length;
        const maxLength = 500;
        $('.character-count').text(`${count}/${maxLength}`);
        
        if (count > maxLength * 0.8) {
            $('.character-count').css('color', 'var(--warning-color)');
        } else {
            $('.character-count').css('color', 'var(--secondary-color)');
        }
    }
    
    function autoResize() {
        const textarea = $('#user-input')[0];
        textarea.style.height = 'auto';
        textarea.style.height = textarea.scrollHeight + 'px';
    }
    
    function scrollToBottom() {
        const messagesDiv = $('#messages')[0];
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
    
    function clearChat() {
        if (confirm('¿Estás seguro de que quieres limpiar el chat?')) {
            $('#messages').empty();
            // Agregar mensaje de bienvenida
            addMessage('¡Hola! Soy tu asistente virtual. ¿En qué puedo ayudarte hoy?', 'bot');
        }
    }
    
    function toggleMinimize() {
        $('.chat-wrapper').toggleClass('minimized');
    }
    
    // Inicializar contador de caracteres
    updateCharacterCount();
    
    // Mensaje de bienvenida inicial
    addMessage('¡Hola! Soy tu asistente virtual. ¿En qué puedo ayudarte hoy?', 'bot');
});
