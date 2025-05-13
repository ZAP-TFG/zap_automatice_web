// Area Chart
const areaCtx = document.getElementById('areaChart').getContext('2d');
new Chart(areaCtx, {
    type: 'line',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [{
            label: 'Vulnerabilities Found',
            data: [100, 200, 150, 300, 250, 400],
            borderColor: 'rgba(0, 123, 255, 1)',
            backgroundColor: 'rgba(0, 123, 255, 0.2)',
        }]
    },
    options: {
        responsive: true,
    }
});

// Bar Chart
const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {
    type: 'bar',
    data: {
        labels: {{ data.chart_data.labels | tojson }},
        datasets: [{
            label: 'Issues by Severity',
            data: {{ data.chart_data.data | tojson }},
            backgroundColor: ['#007bff', '#ffc107', '#fd7e14', '#dc3545']
        }]
    },
    options: {
        responsive: true,
    }
});

const ctx = document.getElementById('radarChart').getContext('2d');

const radarChart = new Chart(ctx, {
  type: 'radar',
  data: {
    labels: {{ data.owasp_top_10.labels | tojson }},
    datasets: [{
      label: 'OWASP TOP 10',
      data: {{data.owasp_top_10.data | tojson}},
      fill: true,
      backgroundColor: 'rgba(54, 162, 235, 0.3)', 
      borderColor: 'rgba(54, 162, 235, 1)',
      borderWidth: 2, 
      pointBackgroundColor: 'rgba(54, 162, 235, 1)',
      pointBorderColor: '#fff',
      pointHoverBackgroundColor: '#fff',
      pointHoverBorderColor: 'rgba(54, 162, 235, 1)'
    }]
  },
  options: {
    responsive: true,
    scales: {
      r: {
        angleLines: { color: "rgba(255, 255, 255, 0.3)" }, /* Líneas más visibles */
        grid: { color: "rgba(255, 255, 255, 0.2)" }, /* Mejor visibilidad */
        pointLabels: { color: "white", font: { size: 14 } }, /* Letras blancas */
        ticks: { color: "white", backdropColor: "transparent", font: { size: 12 } } /* Numeración blanca */
      }
    },
    plugins: {
      legend: {
        position: 'top',
        labels: { color: "white" } /* Leyenda blanca */
      },
      title: {
        display: true,
        text: 'Radar Chart - A01 a A10',
        color: "white"
      }
    }
  }
});

// Configuración del gráfico donut para el progreso
const progressCtx = document.getElementById('scanProgressChart').getContext('2d');
const progressChart = new Chart(progressCtx, {
    type: 'doughnut',
    data: {
        datasets: [{
            data: [0, 100],  // [progreso, restante]
            backgroundColor: ["#3aef37", "#333333"],  // [color progreso, color fondo]
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        radius: '100%',
        cutout: '85%',  // Tamaño del hueco en el centro
        plugins: {
            legend: {
                display: false  // Ocultar leyenda
            },
            tooltip: {
                enabled: false  // Desactivar tooltips
            }
        }
    },
    plugins: [{
        id: 'centerText',
        beforeDraw: function(chart) {
            const width = chart.width;
            const height = chart.height;
            const ctx = chart.ctx;
            
            ctx.restore();
            
            // Texto del porcentaje en el centro
            const fontSize = (height / 114).toFixed(2);
            ctx.font = fontSize + "em sans-serif";
            ctx.textBaseline = "middle";
            ctx.textAlign = "center";
            ctx.fillStyle = "#9b9b9b"; //textto
            
            const text = chart.data.datasets[0].data[0] + "%";
            ctx.fillText(text, width / 2, height / 2);
            
            ctx.save();
        }
    }]
});

// Función para actualizar el gráfico de progreso
function actualizarProgreso() {
    $.ajax({
        url: '/scan_progress',
        type: 'GET',
        dataType: 'json',
        success: function(data) {
            // Actualizar datos del gráfico
            progressChart.data.datasets[0].data = [data.progress, 100 - data.progress];
            progressChart.update();
            
            document.getElementById('ultimoScanner').innerText = data.ultimoScanner;
                document.getElementById('proximoScanner').innerText = data.proximo;
            document.getElementById('proximoScannerFecha').innerText = data.fecha;
           
            // Si no ha terminado, seguir consultando
            if (data.progress < 100) {
                setTimeout(actualizarProgreso, 2000);  // Consultar cada 2 segundos
            }
        },
        error: function(error) {
            console.error("Error al obtener el progreso:", error);
            setTimeout(actualizarProgreso, 5000);  // Reintentar en 5 segundos
        }
    });
}

// Iniciar la actualización al cargar la página
$(document).ready(function() {
    actualizarProgreso();
});

