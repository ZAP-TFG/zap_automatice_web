const scheduleSwitch = document.getElementById('scheduleSwitch');
const scheduleFields = document.getElementById('scheduleFields');

scheduleSwitch.addEventListener('change', () => {
    if (scheduleSwitch.checked) {
        scheduleFields.classList.remove('d-none');
    } else {
        scheduleFields.classList.add('d-none');
    }
});

const apiSwitch = document.getElementById('apiSwitch');
const apiFields = document.getElementById('apiFields');

apiSwitch.addEventListener('change', () => {
    if (apiSwitch.checked) {
        apiFields.classList.remove('d-none');
    } else {
        apiFields.classList.add('d-none');
    }
});

// Enviar formulario
document.getElementById('scanForm').addEventListener('submit', (event) => {
    event.preventDefault();

    // Recoger los datos del formulario
    const url = document.getElementById('scanUrl').value; 
    const intensity = document.getElementById('scanIntensity').value;
    const scheduled = scheduleSwitch.checked;  
    const dateTime = scheduled ? document.getElementById('datetimepicker').value : null;  
    const apiScan = apiSwitch.checked;  
    const file = apiSwitch.checked ? document.getElementById('configFile').files[0] : null;  

    // Validación de campos obligatorios
    if (!url || !intensity) {
        alert('Por favor, complete todos los campos obligatorios.');
        return;
    }

    const formData = new FormData();
    formData.append('url', url);
    formData.append('intensity', intensity);
    formData.append('scheduled', scheduled);
    formData.append('dateTime', dateTime);
    formData.append('apiScan', apiScan);

    if (file) {
        formData.append('file', file);
    }

    // Realizamos la petición AJAX
    fetch('/process_scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())  // Parseamos la respuesta a JSON
    .then(data => {
        if (data.status === 'success') {
            alert(data.message);  // Mostramos un mensaje de éxito
        } else {
            alert('Error al guardar el escaneo: ' + data.message);  // Mensaje de error del servidor
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Hubo un error al procesar el escaneo.');  // Manejo de errores de la red o del servidor
    });
});
