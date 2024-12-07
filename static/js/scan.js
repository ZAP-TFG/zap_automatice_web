
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

    const data = {
        url: document.getElementById('scanUrl').value,
        intensity: document.getElementById('scanIntensity').value,
        scheduled: scheduleSwitch.checked,
        dateTime: scheduleSwitch.checked ? document.getElementById('scanDateTime').value : null,
        apiScan: apiSwitch.checked,
        file: apiSwitch.checked ? document.getElementById('configFile').files[0] : null,
    };

    console.log('Scan data:', data);

    
    alert('Scan configuration saved. Ready to start!');
});
