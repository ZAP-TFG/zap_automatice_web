$(document).ready(function () {
    const calendarEl = document.getElementById('calendar');
    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        events: function (fetchInfo, successCallback, failureCallback) {
            $.ajax({
                url: '/get_calendar_events',
                type: 'GET',
                success: function (data) {
                    successCallback(data);
                },
                error: function () {
                    failureCallback();
                }
            });
        },
        eventClick: function (info) {
            const event = info.event;
            const type = event.extendedProps.type; // Completado o Programado

            if (type === "completed") {
                const vulnerabilities = event.extendedProps.vulnerabilities;
                const high = vulnerabilities.high.join(', ') || '';
                const medium = vulnerabilities.medium.join(', ') || '';
                const low = vulnerabilities.low.join(', ') || '';
                const info = vulnerabilities.info.join(', ') || '';

                document.getElementById('eventDetailsLabel').textContent = `Details for ${event.title}`;
                document.getElementById('eventDetailsContent').innerHTML = `
                    <p><strong>High Vulnerabilities:</strong> ${high}</p>
                    <p><strong>Medium Vulnerabilities:</strong> ${medium}</p>
                    <p><strong>Low Vulnerabilities:</strong> ${low}</p>
                    <p><strong>Info Vulnerabilities:</strong> ${info}</p>
                `;
            } else if (type === "scheduled") {
                const details = info.event.extendedProps.details;
                const fecha = details.fecha;
                const intensidad = details.intensidad;

                document.getElementById('eventDetailsLabel').textContent = `Details for ${event.title}`;
                document.getElementById('eventDetailsContent').innerHTML = `
                    <p><strong>Start:</strong> ${fecha}</p>
                    <p><strong>Intensidad:</strong> ${intensidad}</p>
                `;
            }

            // Mostrar el modal
            const modal = new bootstrap.Modal(document.getElementById('eventDetailsModal'));
            modal.show();
        }
    });
    calendar.render();
});
