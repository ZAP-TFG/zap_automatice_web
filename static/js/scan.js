$(document).ready(function() {
    // Inicializar el datepicker con tema personalizado
    flatpickr("#datetimepicker", {
        enableTime: true,
        dateFormat: "Y-m-d\\TH:i",
        time_24hr: true,
        minuteIncrement: 15,
        altInput: false,
        theme: "material_blue"
    });

    // Función para gestionar required dinámicamente
    function setFieldsRequired(mode) {
        if (mode === 'basic') {
            $('#scanUrl').prop('required', true);
            $('#scanIntensity').prop('required', true);
            $('#planUrl').prop('required', false);
            $('#yamlFile').prop('required', false);
        } else if (mode === 'plan') {
            $('#scanUrl').prop('required', false);
            $('#scanIntensity').prop('required', false);
            $('#planUrl').prop('required', true);
            $('#yamlFile').prop('required', true);
        }
    }

    // Configurar el modo inicial (basic)
    setFieldsRequired('basic');

    // Manejar el cambio entre modos de escaneo con animaciones
    $('input[name="scanMode"]').on('change', function() {
        const selectedMode = $(this).val();
        
        if (selectedMode === 'basic') {
            $('#basicScanFields').removeClass('d-none').hide().fadeIn(300);
            $('#planScanFields').fadeOut(300, function() {
                $(this).addClass('d-none');
            });
            $('#planInfo').fadeOut(300, function() {
                $(this).addClass('d-none');
            });
            setFieldsRequired('basic');
        } else if (selectedMode === 'plan') {
            $('#planScanFields').removeClass('d-none').hide().fadeIn(300);
            $('#basicScanFields').fadeOut(300, function() {
                $(this).addClass('d-none');
            });
            setFieldsRequired('plan');
        }
    });

    // Manejar la subida del archivo YAML (sin parseo, solo feedback visual)
    $('#yamlFile').on('change', function() {
        const file = this.files[0];
        if (file) {
            // Validar extensión del archivo
            const allowedExtensions = ['yml', 'yaml'];
            const fileExtension = file.name.split('.').pop().toLowerCase();
            
            if (!allowedExtensions.includes(fileExtension)) {
                showToast('Por favor, suba un archivo con extensión .yml o .yaml', 'error');
                $(this).val(''); // Limpiar el input
                $('#planInfo').fadeOut(300, function() {
                    $(this).addClass('d-none');
                });
                return;
            }

            // Mostrar información básica del archivo seleccionado
            $('#planDetails').html(`
                <div class="plan-detail-item">
                    <i class="fas fa-file-code"></i>
                    <strong>Archivo:</strong> ${file.name}
                </div>
                <div class="plan-detail-item">
                    <i class="fas fa-weight"></i>
                    <strong>Tamaño:</strong> ${(file.size / 1024).toFixed(1)} KB
                </div>
                <div class="plan-detail-item">
                    <i class="fas fa-check-circle text-success"></i>
                    <strong>Estado:</strong> Listo para enviar
                </div>
            `);
            
            $('#planInfo').removeClass('d-none alert-danger').addClass('alert-success');
            showToast('Archivo YAML seleccionado correctamente', 'success');
            
        } else {
            $('#planInfo').fadeOut(300, function() {
                $(this).addClass('d-none');
            });
        }
    });

    // Manejar el switch para programar el escaneo con animaciones
    $('#scheduleSwitch').on('change', function() {
        if ($(this).is(':checked')) {
            $('#scheduleFields').removeClass('d-none').hide().slideDown(300);
            showToast('Programación de escaneo activada', 'info');
        } else {
            $('#scheduleFields').slideUp(300, function() {
                $(this).addClass('d-none');
            });
        }
    });

    // Validación en tiempo real para email
    $('#email').on('input', function() {
        const email = $(this).val();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (email && !emailRegex.test(email)) {
            $(this).addClass('is-invalid');
        } else {
            $(this).removeClass('is-invalid');
        }
    });

    // Validación en tiempo real para URL del Basic Scan
    $('#scanUrl').on('input', function() {
        const url = $(this).val();
        const urlRegex = /^https?:\/\/.+/;
        
        if (url && !urlRegex.test(url)) {
            $(this).addClass('is-invalid');
        } else {
            $(this).removeClass('is-invalid');
        }
    });

    // Validación para la URL del Plan Scan
    $('#planUrl').on('input', function() {
        const url = $(this).val();
        const urlRegex = /^https?:\/\/.+/;
        
        if (url && !urlRegex.test(url)) {
            $(this).addClass('is-invalid');
        } else {
            $(this).removeClass('is-invalid');
        }
    });

    // Manejar el envío del formulario con mejor UX
    $('#scanForm').on('submit', function(event) {
        event.preventDefault();

        const scanMode = $('input[name="scanMode"]:checked').val();
        const email = $('#email').val().trim();
        const scheduled = $('#scheduleSwitch').is(':checked');
        const dateTime = scheduled ? $('#datetimepicker').val().trim() : null;

        // Validaciones básicas
        if (!email) {
            showToast('Por favor, ingrese un email válido', 'error');
            $('#email').focus();
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showToast('Por favor, ingrese un email válido', 'error');
            $('#email').focus();
            return;
        }

        if (scheduled && !dateTime) {
            showToast('Por favor, seleccione una fecha y hora para el escaneo programado', 'error');
            $('#datetimepicker').focus();
            return;
        }

        // Crear FormData con campos comunes
        const formData = new FormData();
        formData.append('scanMode', scanMode);
        formData.append('email', email);
        formData.append('scheduled', scheduled);
        
        if (scheduled) {
            console.log("Fecha enviada:", dateTime);
            formData.append('dateTime', dateTime);
        }

        // Validaciones específicas por modo
        if (scanMode === 'basic') {
            const url = $('#scanUrl').val().trim();
            const intensity = $('#scanIntensity').val();
            
            if (!url || !intensity) {
                showToast('Por favor, complete todos los campos obligatorios para el Basic Scan', 'error');
                return;
            }

            // Validar formato de URL
            const urlRegex = /^https?:\/\/.+/;
            if (!urlRegex.test(url)) {
                showToast('Por favor, ingrese una URL válida (debe comenzar con http:// o https://)', 'error');
                $('#scanUrl').focus();
                return;
            }
            
            formData.append('url', url);
            formData.append('intensity', intensity);
            
        } else if (scanMode === 'plan') {
            const yamlFile = $('#yamlFile')[0].files[0];
            const url = $('#planUrl').val().trim();
            
            // Validar que se proporcione el archivo YAML
            if (!yamlFile) {
                showToast('Por favor, suba un archivo YAML para el Plan Scan', 'error');
                $('#yamlFile').focus();
                return;
            }
            
            // Validar que se proporcione la URL
            if (!url) {
                showToast('Por favor, ingrese la URL objetivo para el Plan Scan', 'error');
                $('#planUrl').focus();
                return;
            }
            
            // Validar formato de URL
            const urlRegex = /^https?:\/\/.+/;
            if (!urlRegex.test(url)) {
                showToast('Por favor, ingrese una URL válida (debe comenzar con http:// o https://)', 'error');
                $('#planUrl').focus();
                return;
            }
            
            formData.append('url', url);
            formData.append('yamlFile', yamlFile);
        }

        enviarFormulario(formData);
    });

    // Función para enviar los datos con mejor UX
    function enviarFormulario(formData) {
        const submitBtn = $('.btn-scan');
        const originalContent = submitBtn.html();
        
        // Mostrar loading con animación
        submitBtn.prop('disabled', true).html(`
            <i class="fas fa-spinner fa-spin"></i>
            <span>Procesando...</span>
        `);

        $.ajax({
            url: '/process_scan',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(data) {
                if (data.status === 'success') {
                    showToast(data.message, 'success');
                    
                    // Resetear formulario con animación
                    setTimeout(() => {
                        $('#scanForm')[0].reset();
                        $('#scheduleFields').slideUp(300, function() {
                            $(this).addClass('d-none');
                        });
                        $('#planInfo').fadeOut(300, function() {
                            $(this).addClass('d-none');
                        });
                        
                        // Resetear a modo básico
                        $('#basicScan').prop('checked', true);
                        $('#basicScanFields').removeClass('d-none');
                        $('#planScanFields').addClass('d-none');
                        setFieldsRequired('basic');
                        
                        // Limpiar clases de validación
                        $('.is-invalid').removeClass('is-invalid');
                    }, 1000);
                    
                } else {
                    showToast('Error al guardar el escaneo: ' + data.message, 'error');
                }
            },
            error: function(xhr, status, error) {
                console.error('Error:', xhr.responseJSON || error);
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    showToast('Error: ' + xhr.responseJSON.message, 'error');
                } else {
                    showToast('Hubo un error al procesar el escaneo', 'error');
                }
            },
            complete: function() {
                // Restaurar botón
                setTimeout(() => {
                    submitBtn.prop('disabled', false).html(originalContent);
                }, 1000);
            }
        });
    }

    // Función para mostrar toasts
    function showToast(message, type = 'info') {
        const iconClass = type === 'success' ? 'fa-check-circle text-success' : 
                         type === 'error' ? 'fa-exclamation-triangle text-danger' : 
                         'fa-info-circle text-info';
        
        $('#toastMessage').html(`<i class="fas ${iconClass} me-2"></i>${message}`);
        
        const toast = new bootstrap.Toast(document.getElementById('scanToast'));
        toast.show();
    }

    // Inicializar tooltips si existen
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
