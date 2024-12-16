document.getElementById("send-button").addEventListener("click", sendMessage);
document.getElementById("user-input").addEventListener("keypress", function (event) {
    if (event.key === "Enter") sendMessage();
});

function sendMessage() {
    const userInput = document.getElementById("user-input").value.trim();
    if (!userInput) return;

    const messagesDiv = document.getElementById("messages");

    const userMessage = `<div class="text-end mb-3">
        <span class="badge bg-primary text-wrap">${userInput}</span>
    </div>`;
    messagesDiv.innerHTML += userMessage;
    messagesDiv.scrollTop = messagesDiv.scrollHeight;

    // Enviar el mensaje al servidor
    fetch("/api/vulnerabilidaes", {
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

        // Verificar si la respuesta contiene datos para las gráficas
        if (data.chart_data) {
            renderCharts(data.chart_data);
        }
    })
    .catch(error => {
        console.error("Error:", error);
    });

    document.getElementById("user-input").value = "";
}

// Función para renderizar las gráficas
function renderCharts(chartData) {
    // Mostrar el contenedor de las gráficas
    document.getElementById("chart-container").style.display = 'block';

    // Crear la primera gráfica (tarta)
    new Chart(document.getElementById('chart-first'), {
        type: 'pie',
        data: {
            labels: chartData.labels,
            datasets: [{
                label: 'First Scan',
                data: chartData.data_first_row,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(54, 162, 235, 0.2)',
                    'rgba(255, 206, 86, 0.2)',
                    'rgba(75, 192, 192, 0.2)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    callbacks: {
                        label: function(tooltipItem) {
                            return tooltipItem.label + ': ' + tooltipItem.raw + ' vulnerabilidades';
                        }
                    }
                }
            }
        }
    });

    // Crear la segunda gráfica (tarta)
    new Chart(document.getElementById('chart-second'), {
        type: 'pie',
        data: {
            labels: chartData.labels,
            datasets: [{
                label: 'Second Scan',
                data: chartData.data_second_row,
                backgroundColor: [
                    'rgba(153, 102, 255, 0.2)',
                    'rgba(255, 159, 64, 0.2)',
                    'rgba(75, 192, 192, 0.2)',
                    'rgba(255, 99, 132, 0.2)'
                ],
                borderColor: [
                    'rgba(153, 102, 255, 1)',
                    'rgba(255, 159, 64, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(255, 99, 132, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    callbacks: {
                        label: function(tooltipItem) {
                            return tooltipItem.label + ': ' + tooltipItem.raw + ' vulnerabilidades';
                        }
                    }
                }
            }
        }
    });
}
