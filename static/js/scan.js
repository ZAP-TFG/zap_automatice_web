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
        // Leer el archivo JSON como texto
        const reader = new FileReader();
        reader.onload = function(event) {
            const jsonContent = JSON.parse(event.target.result);  // Parseamos el contenido del archivo JSON
            formData.append('file', JSON.stringify(jsonContent));  // Enviamos el contenido como un string JSON

            // Ahora que el archivo está procesado, enviamos el formulario
            enviarFormulario(formData);
        };
        reader.readAsText(file);  // Leemos el archivo como texto
    } else {
        enviarFormulario(formData);
    }
});

// Función para enviar los datos con fetch
function enviarFormulario(formData) {
    fetch('/process_scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())  
    .then(data => {
        if (data.status === 'success') {
            alert(data.message);  
        } else {
            alert('Error al guardar el escaneo: ' + data.message);  
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Hubo un error al procesar el escaneo.');  
    });
}
