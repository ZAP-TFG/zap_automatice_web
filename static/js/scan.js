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


document.getElementById('scanForm').addEventListener('submit', (event) => {
    event.preventDefault();

 
    const url = document.getElementById('scanUrl').value; 
    const intensity = document.getElementById('scanIntensity').value;
    const email = document.getElementById('email').value;
    const scheduled = scheduleSwitch.checked;  
    const dateTime = scheduled ? document.getElementById('datetimepicker').value : null;  
    const apiScan = apiSwitch.checked;  
    const file = apiSwitch.checked ? document.getElementById('configFile').files[0] : null;  


    if (!url || !intensity) {
        alert('Por favor, complete todos los campos obligatorios.');
        return;
    }

    const formData = new FormData();
    formData.append('url', url);
    formData.append('intensity', intensity);
    formData.append('email', email)
    formData.append('scheduled', scheduled);
    formData.append('dateTime', dateTime);
    formData.append('apiScan', apiScan);

    if (file) {
        const reader = new FileReader();
        reader.onload = function(event) {
            const jsonContent = JSON.parse(event.target.result);  
            formData.append('file', JSON.stringify(jsonContent));  
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
