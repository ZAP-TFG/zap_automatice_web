$(document).ready(function() {
    // Inicializar el datepicker sin altInput para asegurarse de obtener únicamente el valor con el formato correcto.
    flatpickr("#datetimepicker", {
        enableTime: true,
        dateFormat: "Y-m-d\\TH:i", // Debe coincidir con "%d/%m/%Y %H:%M" en el servidor.
        time_24hr: true,
        minuteIncrement: 15,
        altInput: false  // Se deshabilita el altInput para evitar valores duplicados o formateos inesperados.
    });

    // Manejar el switch para programar el escaneo.
    $('#scheduleSwitch').on('change', function() {
        if ($(this).is(':checked')) {
            $('#scheduleFields').removeClass('d-none');
        } else {
            $('#scheduleFields').addClass('d-none');
        }
    });

    // Manejar el envío del formulario.
    $('#scanForm').on('submit', function(event) {
        event.preventDefault();

        const url = $('#scanUrl').val();
        const intensity = $('#scanIntensity').val();
        const email = $('#email').val();
        const scheduled = $('#scheduleSwitch').is(':checked');
        // Se utiliza trim() para limpiar posibles espacios adicionales en el valor.
        const dateTime = scheduled ? $('#datetimepicker').val().trim() : null;

        if (!url || !intensity) {
            alert('Por favor, complete todos los campos obligatorios.');
            return;
        }

        // Si es un escaneo programado, se verifica que se haya establecido la fecha.
        if (scheduled && !dateTime) {
            alert('Por favor, seleccione una fecha y hora para el escaneo programado.');
            return;
        }

        // Crear y llenar el objeto FormData.
        let formData = new FormData();
        formData.append('url', url);
        formData.append('intensity', intensity);
        formData.append('email', email);
        formData.append('scheduled', scheduled);
        if (scheduled) {
            console.log("Fecha enviada:", dateTime);
            formData.append('dateTime', dateTime);
        }

        enviarFormulario(formData);
    });

    // Función para enviar los datos usando jQuery ajax.
    function enviarFormulario(formData) {
        $.ajax({
            url: '/process_scan',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(data) {
                if (data.status === 'success') {
                    alert(data.message);
                    $('#scanForm')[0].reset();
                    $('#scheduleFields').addClass('d-none');
                } else {
                    alert('Error al guardar el escaneo: ' + data.message);
                }
            },
            error: function(xhr, status, error) {
                console.error('Error:', xhr.responseJSON || error);
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    alert('Error: ' + xhr.responseJSON.message);
                } else {
                    alert('Hubo un error al procesar el escaneo.');
                }
            }
        });
    }
});
