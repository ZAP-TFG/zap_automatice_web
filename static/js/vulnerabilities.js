$(document).ready(function() {
    // Referencias a las gráficas de Chart.js
    let pieChartNew, pieChartPast;

    $('#vulnerabilitiesForm').on('submit', function(event) {
        event.preventDefault(); 

        const url = $('#scanUrl').val(); 

        if (!url) {
            alert("Por favor, introduce una URL.");
            return;
        }

        $.ajax({
            url: '/vulnerabilidades_graficas', 
            type: 'POST',
            data: { url: url }, 
            success: function(response) {
                const newData = response.data1.pieChartNew.data;
                const pastData = response.data2.pieChartPast.data;

                // Crear o actualizar gráficas
                if (pieChartNew) {
                    pieChartNew.data.datasets[0].data = newData;
                    pieChartNew.update();
                } else {
                    pieChartNew = new Chart(document.getElementById('pieChartNew'), {
                        type: 'pie',
                        data: {
                            labels: response.data1.pieChartNew.labels,
                            datasets: [{
                                data: newData,
                                backgroundColor: ['#4caf50', '#ffeb3b', '#ff9800', '#f44336']
                            }]
                        }
                    });
                }

                if (pieChartPast) {
                    pieChartPast.data.datasets[0].data = pastData;
                    pieChartPast.update();
                } else {
                    pieChartPast = new Chart(document.getElementById('pieChartPast'), {
                        type: 'pie',
                        data: {
                            labels: response.data2.pieChartPast.labels,
                            datasets: [{
                                data: pastData,
                                backgroundColor: ['#4caf50', '#ffeb3b', '#ff9800', '#f44336']
                            }]
                        }
                    });
                }

                // Actualizar tablas de alertas
                $('#alertsOldTable').empty();
                response.data3.alertsOld.forEach(alert => {
                    $('#alertsOldTable').append(`
                        <tr>
                            <td>${alert.riskdesc}</td>
                            <td>${alert.alert}</td>
                        </tr>
                    `);
                });

                $('#alertsNewTable').empty();
                response.data4.alertsNew.forEach(alert => {
                    $('#alertsNewTable').append(`
                        <tr>
                            <td>${alert.riskdesc}</td>
                            <td>${alert.alert}</td>
                        </tr>
                    `);
                });
            },
            error: function(xhr) {
                alert("Error: " + xhr.responseJSON.error);
            }
        });

        $.ajax({
            url: '/vulnerabilidades_chatgpt',
            type: 'POST',
            data: { url: url },
            success: function(response) {
                // Mostrar la comparativa en el contenedor
                const convert = new showdown.Converter();
                const html = convert.makeHtml(response.comparativa)
                $('#chatgptResponse').html(html);
            },
            error: function(xhr) {
                $('#chatgptResponse').text("Error: " + (xhr.responseJSON.error || "No se pudo generar la comparativa."));
            }
        });
    });
});
