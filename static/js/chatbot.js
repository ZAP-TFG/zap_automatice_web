document.getElementById("send-button").addEventListener("click", sendMessage);
document.getElementById("user-input").addEventListener("keypress", function (event) {
    if (event.key === "Enter") sendMessage();
});
document.getElementById("config-button").addEventListener("click", sendConfig);

function sendConfig() {
    const userInputConfig = document.getElementById("user-input").value.trim();
    if (!userInputConfig) return;

    fetch("/chatconfig", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ message: userInputConfig })
    })
    .then(response => response.json())
    .then(data => {
        const messagesDiv = document.getElementById("messages");

        const botReply = `<div class="text-start mb-3">
            <span class="badge bg-secondary text-wrap">${data.reply || "Error en el servidor."}</span>
        </div>`;
        messagesDiv.innerHTML += botReply;
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    })
    .catch(error => {
        console.error("Error:", error);
    });
    document.getElementById("user-input").value = "";
}

function sendMessage() {
    const userInput = document.getElementById("user-input").value.trim();
    if (!userInput) return;

    const messagesDiv = document.getElementById("messages");

    
    const userMessage = `<div class="text-end mb-3">
        <span class="badge bg-primary text-wrap">${userInput}</span>
    </div>`;
    messagesDiv.innerHTML += userMessage;
    messagesDiv.scrollTop = messagesDiv.scrollHeight;

    
    fetch("/chatget", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ message: userInput })
    })
    .then(response => response.json())
    .then(data => {
        const botReply = `<div class="text-start mb-3">
            <span class="badge bg-secondary text-wrap">${data.reply || "Error en el servidor."}</span>
        </div>`;
        messagesDiv.innerHTML += botReply;
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    })
    .catch(error => {
        console.error("Error:", error);
    });

    document.getElementById("user-input").value = "";
}
