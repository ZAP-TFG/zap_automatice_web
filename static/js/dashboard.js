$(document).ready(function() {
    // Inicialización de componentes
    initializeCharts();
    initializeTooltips();
    initializeAlerts();
    startProgressMonitoring();
    
    // Configuraciones globales de Chart.js con colores corporativos
    Chart.defaults.color = '#a0aec0';
    Chart.defaults.borderColor = '#2d3748';
    Chart.defaults.backgroundColor = 'rgba(0, 48, 89, 0.1)'; // Azul corporativo
});

// ===== NUEVAS FUNCIONES DE ALERTAS =====

// Inicializar funcionalidades de alertas
function initializeAlerts() {
    loadLastScanAlerts();
    initializeSearch();
    
    // Event listeners
    $('#refreshLastScan').on('click', refreshLastScanAlerts);
    $('#exportLastScan').on('click', exportLastScanAlerts);
    $('#searchAlertsBtn').on('click', searchAlerts);
    $('#urlSearchInput').on('keypress', function(e) {
        if (e.which === 13) {
            searchAlerts();
        }
    });
    
    // Actualizar alertas cada 2 minutos
    setInterval(loadLastScanAlerts, 120000);
}

// Cargar alertas del último escáner
function loadLastScanAlerts() {
    const alertsList = $('#lastScanAlertsList');
    const titleElement = $('#lastScanAlertsTitle');
    
    // Mostrar loading
    alertsList.html('<div class="loading-state"><i class="fas fa-spinner fa-spin"></i><p>Cargando alertas...</p></div>');
    
    $.ajax({
        url: '/last_scan_alerts',
        type: 'GET',
        dataType: 'json',
        timeout: 15000,
        success: function(data) {
            updateLastScanSummary(data.summary || {});
            displayLastScanAlerts(data.alerts || []);
            
            // NUEVO: Actualizar título con la URL
            if (data.scan_info && data.scan_info.target_url) {
                titleElement.html(`
                    <i class="fas fa-bell"></i>
                    Alertas del Último Escáner <span class="url-subtitle">(${data.scan_info.target_url})</span>
                `);
            } else {
                // Mantener título por defecto si no hay URL
                titleElement.html(`
                    <i class="fas fa-bell"></i>
                    Alertas del Último Escáner
                `);
            }
        },
        error: function(xhr, status, error) {
            console.error('Error al cargar alertas del último escáner:', error);
            
            // Restablecer título por defecto en caso de error
            titleElement.html(`
                <i class="fas fa-bell"></i>
                Alertas del Último Escáner
            `);
            
            // Mostrar datos de ejemplo si el endpoint no existe
            if (xhr.status === 404) {
                const exampleData = {
                    summary: { high: 3, medium: 8, low: 12 },
                    alerts: [
                        {
                            id: 1,
                            title: "SQL Injection Detectada",
                            description: "Posible vulnerabilidad de inyección SQL en formulario de login",
                            severity: "high",
                            created_at: new Date(Date.now() - 3600000).toISOString()
                        },
                        {
                            id: 2,
                            title: "Cross-Site Scripting (XSS)",
                            description: "Campo de búsqueda vulnerable a ataques XSS",
                            severity: "medium",
                            created_at: new Date(Date.now() - 7200000).toISOString()
                        },
                        {
                            id: 3,
                            title: "Información Sensible Expuesta",
                            description: "Headers revelando versión del servidor",
                            severity: "low",
                            created_at: new Date(Date.now() - 10800000).toISOString()
                        }
                    ]
                };
                updateLastScanSummary(exampleData.summary);
                displayLastScanAlerts(exampleData.alerts);
            } else {
                alertsList.html(`
                    <div class="no-results-state">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Error al cargar las alertas</p>
                    </div>
                `);
            }
        }
    });
}

// Actualizar resumen de alertas del último escáner
function updateLastScanSummary(summary) {
    $('#lastScanHighCount').text(summary.high || 0);
    $('#lastScanMediumCount').text(summary.medium || 0);
    $('#lastScanLowCount').text(summary.low || 0);
}

// Mostrar alertas del último escáner
function displayLastScanAlerts(alerts) {
    const alertsList = $('#lastScanAlertsList');
    
    if (!alerts || alerts.length === 0) {
        alertsList.html(`
            <div class="no-results-state">
                <i class="fas fa-check-circle"></i>
                <p>No se encontraron alertas en el último escáner</p>
            </div>
        `);
        return;
    }
    
    let html = '';
    alerts.forEach(alert => {
        const timeAgo = formatTimeAgo(alert.created_at);
        html += `
            <div class="alert-item" data-alert-id="${alert.id}">
                <div class="alert-severity ${alert.severity}"></div>
                <div class="alert-details">
                    <h6>${alert.title}</h6>
                    <p>${alert.description}</p>
                </div>
                <div class="alert-time">${timeAgo}</div>
            </div>
        `;
    });
    
    alertsList.html(html);
    
    // Event listener para ver detalles de alerta
    $('.alert-item').on('click', function() {
        const alertId = $(this).data('alert-id');
        showAlertDetails(alertId);
    });
}

// Refrescar alertas del último escáner
function refreshLastScanAlerts() {
    const btn = $('#refreshLastScan');
    const icon = btn.find('i');
    
    // Animar botón
    icon.addClass('fa-spin');
    btn.prop('disabled', true);
    
    loadLastScanAlerts();
    
    setTimeout(() => {
        icon.removeClass('fa-spin');
        btn.prop('disabled', false);
        showToast('Alertas actualizadas', 'success');
    }, 2000);
}

// Exportar alertas del último escáner
function exportLastScanAlerts() {
    const btn = $('#exportLastScan');
    btn.prop('disabled', true);
    
    // Simular exportación por ahora
    setTimeout(() => {
        showToast('Funcionalidad de exportación en desarrollo', 'info');
        btn.prop('disabled', false);
    }, 1000);
}

// Inicializar búsqueda de alertas
function initializeSearch() {
    const searchResults = $('#searchResults');
    searchResults.html(`
        <div class="no-search-state">
            <i class="fas fa-search"></i>
            <p>Ingrese una URL para comenzar la búsqueda</p>
        </div>
    `);
}

// Buscar alertas por URL
function searchAlerts() {
    const url = $('#urlSearchInput').val().trim();
    const severity = $('#severityFilter').val();
    const days = $('#dateFilter').val();
    const searchResults = $('#searchResults');
    const searchBtn = $('#searchAlertsBtn');
    
    if (!url) {
        showToast('Por favor ingrese una URL para buscar', 'warning');
        return;
    }
    
    // Actualizar estado
    updateSearchStatus('searching');
    searchBtn.prop('disabled', true);
    
    // Mostrar loading
    searchResults.html(`
        <div class="loading-state">
            <i class="fas fa-spinner fa-spin"></i>
            <p>Buscando alertas...</p>
        </div>
    `);
    
    $.ajax({
        url: '/search_alerts',
        type: 'POST',
        data: JSON.stringify({
            url: url,
            severity: severity,
            days: days
        }),
        contentType: 'application/json',
        dataType: 'json',
        timeout: 15000,
        success: function(data) {
            displaySearchResults(data.results || [], url);
            updateSearchStatus('completed', (data.results || []).length);
        },
        error: function(xhr, status, error) {
            console.error('Error en búsqueda:', error);
            
            // Mostrar datos de ejemplo si el endpoint no existe
            if (xhr.status === 404) {
                const exampleResults = [
                    {
                        url: url,
                        total_alerts: 5,
                        alerts_by_severity: {
                            high: 1,
                            medium: 2,
                            low: 1,
                            info: 1
                        }
                    }
                ];
                displaySearchResults(exampleResults, url);
                updateSearchStatus('completed', exampleResults.length);
            } else {
                searchResults.html(`
                    <div class="no-results-state">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Error al realizar la búsqueda</p>
                    </div>
                `);
                updateSearchStatus('error');
            }
        },
        complete: function() {
            searchBtn.prop('disabled', false);
        }
    });
}

// CAMBIO PRINCIPAL: Mostrar resultados de búsqueda (MODIFICADO PARA MOSTRAR CADA ESCANEO POR SEPARADO)
function displaySearchResults(results, searchUrl) {
    const searchResults = $('#searchResults');
    
    if (!results || results.length === 0) {
        searchResults.html(`
            <div class="no-results-state">
                <i class="fas fa-search"></i>
                <p>No se encontraron alertas para "${searchUrl}"</p>
            </div>
        `);
        return;
    }
    
    let html = '';
    
    // CAMBIO: Mostrar cada escaneo por separado con su fecha
    results.forEach(result => {
        const alertBadges = createAlertBadges(result.alerts_by_severity);
        const scanDate = result.scan_date_formatted || formatDateTime(result.scan_date) || 'Fecha no disponible';
        
        html += `
            <div class="search-result-item" data-url="${result.url}" data-scan-id="${result.scan_id}">
                <div class="result-header">
                    <div class="result-url">
                        <i class="fas fa-link"></i>
                        <span style="color: #ffffff;">${result.url}</span>
                    </div>
                    <div class="result-date">
                        <i class="fas fa-calendar"></i>
                        <span>${scanDate}</span>
                    </div>
                </div>
                <div class="result-summary">
                    <div class="result-count">${result.total_alerts} alertas</div>
                    <div class="result-alerts">
                        ${alertBadges}
                    </div>
                </div>
            </div>
        `;
    });
    
    searchResults.html(html);
    
    // CAMBIO: Event listener actualizado para pasar scan_id específico
    $('.search-result-item').on('click', function() {
        const url = $(this).data('url');
        const scanId = $(this).data('scan-id');
        showUrlAlertDetails(url, scanId);
    });
}

// Crear badges de alertas (MEJORADO CON EVENT LISTENERS)
function createAlertBadges(alertsBySeverity) {
    let badges = '';
    
    if (alertsBySeverity.high > 0) {
        badges += `<span class="result-alert-badge high" data-severity="high">${alertsBySeverity.high} Altas</span>`;
    }
    if (alertsBySeverity.medium > 0) {
        badges += `<span class="result-alert-badge medium" data-severity="medium">${alertsBySeverity.medium} Medias</span>`;
    }
    if (alertsBySeverity.low > 0) {
        badges += `<span class="result-alert-badge low" data-severity="low">${alertsBySeverity.low} Bajas</span>`;
    }
    if (alertsBySeverity.info > 0) {
        badges += `<span class="result-alert-badge info" data-severity="informational">${alertsBySeverity.info} Informativas</span>`;
    }
    
    return badges;
}

// Actualizar estado de búsqueda
function updateSearchStatus(status, resultCount = 0) {
    const statusElement = $('#searchStatus');
    const indicator = statusElement.find('.status-indicator');
    const text = statusElement.find('span');
    
    switch(status) {
        case 'searching':
            indicator.removeClass('inactive').addClass('searching');
            text.text('Buscando...');
            break;
        case 'completed':
            indicator.removeClass('searching inactive');
            text.text(`${resultCount} resultado(s) encontrado(s)`);
            break;
        case 'error':
            indicator.removeClass('searching').addClass('inactive');
            text.text('Error en búsqueda');
            break;
        default:
            indicator.removeClass('searching').addClass('inactive');
            text.text('Sin consulta');
    }
}

// Mostrar detalles de alerta específica
function showAlertDetails(alertId) {
    // Obtener datos detallados del último escaneo
    $.ajax({
        url: '/last_scan_alerts',
        type: 'GET',
        dataType: 'json',
        success: function(data) {
            // Buscar la alerta específica en los datos
            const alert = data.alerts.find(a => a.id === alertId);
            
            if (alert) {
                displayAlertDetails(alert);
            } else {
                showToast('No se encontraron detalles para esta alerta', 'error');
            }
        },
        error: function() {
            showToast('Error al cargar detalles de la alerta', 'error');
        }
    });
}

// CAMBIO: Mostrar detalles de alertas por URL específica (MODIFICADO PARA USAR SCAN_ID)
function showUrlAlertDetails(url, scanId) {
    // Abrir modal inmediatamente
    $('#urlAlertsModal').modal('show');
    $('#urlAlertsModalLabel').html(`<i class="fas fa-search"></i> Alertas para: ${url}`);
    
    // Mostrar loading
    $('#urlAlertsContent').html(`
        <div class="text-center">
            <i class="fas fa-spinner fa-spin fa-2x"></i>
            <p class="mt-2">Cargando alertas del escaneo específico...</p>
        </div>
    `);
    
    // Obtener todas las severidades para el escaneo específico
    loadAllSeveritiesForScan(url, scanId);
}

// NUEVA FUNCIÓN: Cargar todas las severidades para un escaneo específico
function loadAllSeveritiesForScan(url, scanId) {
    const severities = ['high', 'medium', 'low', 'informational'];
    let allAlerts = [];
    let completedRequests = 0;
    let scanDate = '';
    
    severities.forEach(severity => {
        $.ajax({
            url: '/alert_details_by_severity',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                url: url,
                severity: severity,
                scan_id: scanId  // CLAVE: usar scan_id específico
            }),
            success: function(data) {
                if (data.alerts && data.alerts.length > 0) {
                    allAlerts = allAlerts.concat(data.alerts.map(alert => ({
                        ...alert,
                        severity: severity
                    })));
                }
                
                // Capturar fecha del escaneo
                if (data.scan_date && !scanDate) {
                    scanDate = data.scan_date;
                }
                
                completedRequests++;
                if (completedRequests === severities.length) {
                    displayAllAlertsInModal(allAlerts, url, scanDate, scanId);
                }
            },
            error: function(error) {
                console.error(`Error al cargar alertas ${severity}:`, error);
                completedRequests++;
                if (completedRequests === severities.length) {
                    displayAllAlertsInModal(allAlerts, url, scanDate, scanId);
                }
            }
        });
    });
}

// NUEVA FUNCIÓN: Mostrar todas las alertas en el modal
function displayAllAlertsInModal(alerts, url, scanDate, scanId) {
    if (alerts.length === 0) {
        $('#urlAlertsContent').html(`
            <div class="no-results-state">
                <i class="fas fa-shield-alt"></i>
                <p>No se encontraron alertas para este escaneo específico</p>
            </div>
        `);
        return;
    }
    
    // Agrupar por severidad
    const groupedAlerts = {
        high: alerts.filter(a => a.severity === 'high'),
        medium: alerts.filter(a => a.severity === 'medium'),
        low: alerts.filter(a => a.severity === 'low'),
        informational: alerts.filter(a => a.severity === 'informational')
    };
    
    let html = `
        <div class="url-alerts-container">
            <div class="url-header mb-3">
                <h4>${url}</h4>
                <p class="text-muted">Escaneo del: ${scanDate || 'Fecha no disponible'}</p>
                <div class="alert-summary-badges">
                    ${groupedAlerts.high.length > 0 ? `<span class="badge bg-danger">${groupedAlerts.high.length} Altas</span>` : ''}
                    ${groupedAlerts.medium.length > 0 ? `<span class="badge bg-warning">${groupedAlerts.medium.length} Medias</span>` : ''}
                    ${groupedAlerts.low.length > 0 ? `<span class="badge bg-info">${groupedAlerts.low.length} Bajas</span>` : ''}
                    ${groupedAlerts.informational.length > 0 ? `<span class="badge bg-secondary">${groupedAlerts.informational.length} Informativas</span>` : ''}
                </div>
            </div>
            
            <div class="severity-sections">
    `;
    
    Object.entries(groupedAlerts).forEach(([severity, severityAlerts]) => {
        if (severityAlerts.length > 0) {
            const severityName = {
                high: 'Altas',
                medium: 'Medias', 
                low: 'Bajas',
                informational: 'Informativas'
            }[severity];
            
            html += createSeveritySection(severity, severityName, severityAlerts.length, scanId, url);
        }
    });
    
    html += `
            </div>
        </div>
    `;
    
    $('#urlAlertsContent').html(html);
}

// Función para mostrar detalles de una alerta en modal (MEJORADO)
function displayAlertDetails(alert) {
    const severityClass = getSeverityClass(alert.severity);
    const severityIcon = getSeverityIcon(alert.severity);
    
    const content = `
        <div class="alert-detail-container">
            <div class="alert-header-detail mb-3">
                <div class="d-flex align-items-center mb-2">
                    <span class="severity-badge ${severityClass} me-3">
                        <i class="${severityIcon}"></i>
                        ${getSeverityLabel(alert.severity)}
                    </span>
                    <span class="text-muted">ID: ${alert.id}</span>
                </div>
                <h4 class="text-light">${alert.title}</h4>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="detail-section mb-3">
                        <h6><i class="fas fa-info-circle"></i> Información General</h6>
                        <table class="table table-dark table-sm">
                            <tr><td>Confianza:</td><td>${alert.confidence || 'N/A'}</td></tr>
                            <tr><td>Instancias:</td><td>${alert.count}</td></tr>
                            <tr><td>CWE ID:</td><td>${alert.cweid || 'N/A'}</td></tr>
                            <tr><td>Fecha:</td><td>${formatDateTime(alert.created_at)}</td></tr>
                        </table>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="detail-section mb-3">
                        <h6><i class="fas fa-shield-alt"></i> Nivel de Riesgo</h6>
                        <div class="risk-indicator ${severityClass}">
                            <i class="${severityIcon} fa-2x"></i>
                            <div class="ms-3">
                                <div class="risk-level">${getSeverityLabel(alert.severity)}</div>
                                <div class="risk-desc">${alert.riskdesc || alert.severity}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="detail-section mb-3">
                <h6><i class="fas fa-file-alt"></i> Descripción</h6>
                <div class="description-box">
                    ${alert.description || 'Sin descripción disponible'}
                </div>
            </div>
            
            ${alert.evidence ? `
            <div class="detail-section mb-3">
                <h6><i class="fas fa-search"></i> Evidencia</h6>
                <div class="code-box">
                    <pre><code>${escapeHtml(alert.evidence)}</code></pre>
                </div>
            </div>
            ` : ''}
            
            ${alert.attack ? `
            <div class="detail-section mb-3">
                <h6><i class="fas fa-bug"></i> Ataque</h6>
                <div class="code-box">
                    <pre><code>${escapeHtml(alert.attack)}</code></pre>
                </div>
            </div>
            ` : ''}
            
            ${alert.reference ? `
            <div class="detail-section mb-3">
                <h6><i class="fas fa-external-link-alt"></i> Referencias</h6>
                <div class="references-box">
                    ${formatReferences(alert.reference)}
                </div>
            </div>
            ` : ''}
        </div>
    `;
    
    $('#alertDetailsContent').html(content);
    $('#alertDetailsModal').modal('show');
    
    // Configurar botón de copiar
    $('#copyAlertDetails').off('click').on('click', function() {
        copyAlertDetailsToClipboard(alert);
    });
}

// Funciones auxiliares
function getSeverityClass(severity) {
    const classes = {
        'high': 'severity-high',
        'medium': 'severity-medium', 
        'low': 'severity-low',
        'informational': 'severity-info'
    };
    return classes[severity] || 'severity-info';
}

function getSeverityIcon(severity) {
    const icons = {
        'high': 'fas fa-exclamation-triangle',
        'medium': 'fas fa-exclamation-circle',
        'low': 'fas fa-info-circle', 
        'informational': 'fas fa-info'
    };
    return icons[severity] || 'fas fa-info';
}

function getSeverityLabel(severity) {
    const labels = {
        'high': 'Alta',
        'medium': 'Media',
        'low': 'Baja',
        'informational': 'Informativa'
    };
    return labels[severity] || 'Informativa';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDateTime(dateString) {
    if (!dateString) return 'Fecha no disponible';
    const date = new Date(dateString);
    return date.toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatReferences(references) {
    if (!references) return 'Sin referencias';
    
    return references.split('\n').map(ref => {
        if (ref.trim().startsWith('http')) {
            return `<a href="${ref.trim()}" target="_blank" class="text-info">${ref.trim()}</a>`;
        }
        return ref.trim();
    }).join('<br>');
}

function createSeveritySection(severity, label, count, scanId, url) {
    const severityClass = getSeverityClass(severity);
    const severityIcon = getSeverityIcon(severity);
    
    return `
        <div class="severity-section mb-3">
            <div class="severity-header ${severityClass} p-2 rounded-top">
                <i class="${severityIcon}"></i>
                <strong>${label} (${count})</strong>
            </div>
            <div class="severity-content p-3 border border-top-0 rounded-bottom">
                <button class="btn btn-outline-light btn-sm" onclick="loadSeverityDetails('${scanId || 'unknown'}', '${severity}', '${url || ''}')">
                    <i class="fas fa-eye"></i> Ver Detalles
                </button>
            </div>
        </div>
    `;
}

// CAMBIO: Cargar detalles por severidad (MODIFICADO PARA USAR SCAN_ID)
function loadSeverityDetails(scanId, severity, url) {
    // Mostrar modal de loading
    $('#severityDetailsContent').html(`
        <div class="text-center">
            <i class="fas fa-spinner fa-spin fa-2x"></i>
            <p class="mt-2">Cargando detalles de alertas ${getSeverityLabel(severity)}...</p>
        </div>
    `);
    $('#severityDetailsModalLabel').html(`<i class="fas fa-list"></i> Alertas ${getSeverityLabel(severity)} - ${url}`);
    $('#severityDetailsModal').modal('show');
    
    // CAMBIO: Llamar al endpoint incluyendo scan_id específico
    $.ajax({
        url: `/alert_details_by_severity`,
        type: 'POST',
        data: JSON.stringify({
            url: url,
            severity: severity,
            scan_id: scanId  // CLAVE: incluir scan_id específico
        }),
        contentType: 'application/json',
        dataType: 'json',
        success: function(data) {
            displaySeverityDetails(data.alerts || [], severity, url, data.scan_date);
        },
        error: function(xhr, status, error) {
            console.error('Error al cargar detalles de severidad:', error);
            $('#severityDetailsContent').html(`
                <div class="text-center text-danger">
                    <i class="fas fa-exclamation-triangle fa-2x"></i>
                    <p class="mt-2">Error al cargar los detalles</p>
                </div>
            `);
        }
    });
}

// MEJORADO: Mostrar detalles por severidad con información del escaneo
function displaySeverityDetails(alerts, severity, url, scanDate) {
    if (!alerts || alerts.length === 0) {
        $('#severityDetailsContent').html(`
            <div class="text-center text-muted">
                <i class="fas fa-info-circle fa-2x"></i>
                <p class="mt-2">No hay alertas de nivel ${getSeverityLabel(severity)} para este escaneo</p>
            </div>
        `);
        return;
    }
    
    let html = `
        <div class="severity-details-container">
            <div class="mb-3">
                <h5>Alertas ${getSeverityLabel(severity)} encontradas: ${alerts.length}</h5>
                <p class="text-muted">URL: ${url}</p>
                ${scanDate ? `<p class="text-muted">Fecha del escaneo: ${scanDate}</p>` : ''}
            </div>
            <div class="alerts-details-list">
    `;
    
    alerts.forEach((alert, index) => {
        const severityClass = getSeverityClass(severity);
        const severityIcon = getSeverityIcon(severity);
        
        html += `
            <div class="alert-detail-item mb-4 p-3 border rounded ${severityClass}-border">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <h6 class="mb-0">
                        <i class="${severityIcon}"></i>
                        ${alert.name || 'Sin nombre'}
                    </h6>
                    <span class="badge ${severityClass}">${getSeverityLabel(severity)}</span>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Confianza:</strong> ${alert.confidence || 'N/A'}</p>
                        <p><strong>Instancias:</strong> ${alert.count || 1}</p>
                        <p><strong>CWE ID:</strong> ${alert.cweid || 'N/A'}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Risk Description:</strong> ${alert.riskdesc || 'N/A'}</p>
                    </div>
                </div>
                
                ${alert.description ? `
                <div class="mb-2">
                    <strong>Descripción:</strong>
                    <div class="description-text p-2 bg-dark rounded">${alert.description}</div>
                </div>
                ` : ''}
                
                ${alert.evidence ? `
                <div class="mb-2">
                    <strong>Evidencia:</strong>
                    <div class="code-text p-2 bg-dark rounded">
                        <pre><code>${escapeHtml(alert.evidence)}</code></pre>
                    </div>
                </div>
                ` : ''}
                
                ${alert.attack ? `
                <div class="mb-2">
                    <strong>Ataque:</strong>
                    <div class="code-text p-2 bg-dark rounded">
                        <pre><code>${escapeHtml(alert.attack)}</code></pre>
                    </div>
                </div>
                ` : ''}
                
                ${alert.reference ? `
                <div class="mb-2">
                    <strong>Referencias:</strong>
                    <div class="references-text p-2 bg-dark rounded">
                        ${formatReferences(alert.reference)}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    });
    
    html += `
            </div>
        </div>
    `;
    
    $('#severityDetailsContent').html(html);
}

function copyAlertDetailsToClipboard(alert) {
    const text = `
ALERTA DE SEGURIDAD
==================
Título: ${alert.title}
Severidad: ${getSeverityLabel(alert.severity)}
Confianza: ${alert.confidence || 'N/A'}
CWE ID: ${alert.cweid || 'N/A'}
Instancias: ${alert.count}

Descripción:
${alert.description || 'Sin descripción'}

${alert.evidence ? `Evidencia:\n${alert.evidence}\n` : ''}
${alert.attack ? `Ataque:\n${alert.attack}\n` : ''}
${alert.reference ? `Referencias:\n${alert.reference}` : ''}
    `.trim();
    
    navigator.clipboard.writeText(text).then(() => {
        showToast('Detalles copiados al portapapeles', 'success');
    }).catch(() => {
        showToast('Error al copiar al portapapeles', 'error');
    });
}

// Formatear tiempo relativo
function formatTimeAgo(dateString) {
    const now = new Date();
    const date = new Date(dateString);
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) return 'Hace unos momentos';
    if (diffInSeconds < 3600) return `Hace ${Math.floor(diffInSeconds / 60)} minutos`;
    if (diffInSeconds < 86400) return `Hace ${Math.floor(diffInSeconds / 3600)} horas`;
    return `Hace ${Math.floor(diffInSeconds / 86400)} días`;
}

// ===== FUNCIONES EXISTENTES =====

// Función para inicializar todos los gráficos
function initializeCharts() {
    initAreaChart();
    initBarChart();
    initRadarChart();
    initProgressChart();
}

// Gráfico de área - Tendencias
function initAreaChart() {
    const areaCtx = document.getElementById('areaChart').getContext('2d');
    
    new Chart(areaCtx, {
        type: 'line',
        data: {
            labels: ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun'],
            datasets: [{
                label: 'Vulnerabilidades Encontradas',
                data: [100, 200, 150, 300, 250, 400],
                borderColor: '#FF2778',
                backgroundColor: 'rgba(255, 39, 120, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#FF2778',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointRadius: 6,
                pointHoverRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: '#1a1f2e',
                    titleColor: '#ffffff',
                    bodyColor: '#a0aec0',
                    borderColor: '#FF2778',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(45, 55, 72, 0.5)'
                    },
                    ticks: {
                        color: '#a0aec0'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(45, 55, 72, 0.5)'
                    },
                    ticks: {
                        color: '#a0aec0'
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

// Gráfico de barras - Severidad
function initBarChart() {
    const barCtx = document.getElementById('barChart').getContext('2d');
    
    const chartData = window.dashboardData?.chartData || {
        labels: ['Info', 'Low', 'Medium', 'High'],
        data: [10, 25, 15, 5]
    };
    
    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: chartData.labels,
            datasets: [{
                label: 'Issues por Severidad',
                data: chartData.data,
                backgroundColor: [
                    'rgba(13, 202, 240, 0.8)',  // Info - Azul
                    'rgba(255, 193, 7, 0.8)',   // Low - Amarillo
                    'rgba(253, 126, 20, 0.8)',  // Medium - Naranja
                    'rgba(220, 53, 69, 0.8)'    // High - Rojo
                ],
                borderColor: [
                    '#0dcaf0',  // Info - Azul
                    '#ffc107',  // Low - Amarillo
                    '#fd7e14',  // Medium - Naranja
                    '#dc3545'   // High - Rojo
                ],
                borderWidth: 2,
                borderRadius: 8,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: '#1a1f2e',
                    titleColor: '#ffffff',
                    bodyColor: '#a0aec0',
                    borderColor: '#FF2778',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#a0aec0'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(45, 55, 72, 0.5)'
                    },
                    ticks: {
                        color: '#a0aec0'
                    }
                }
            }
        }
    });
    
    createSeverityLegend(chartData.labels);
}

// Crear leyenda personalizada para severidad
function createSeverityLegend(labels) {
    const legendContainer = document.getElementById('severityLegend');
    if (!legendContainer) return;
    
    const colors = ['#0dcaf0', '#ffc107', '#fd7e14', '#dc3545'];
    
    legendContainer.innerHTML = '';
    
    labels.forEach((label, index) => {
        const legendItem = document.createElement('div');
        legendItem.className = 'legend-item';
        
        const colorBox = document.createElement('div');
        colorBox.className = 'legend-color';
        colorBox.style.backgroundColor = colors[index] || '#0dcaf0';
        
        const labelText = document.createElement('span');
        labelText.textContent = label;
        
        legendItem.appendChild(colorBox);
        legendItem.appendChild(labelText);
        legendContainer.appendChild(legendItem);
    });
}

// Gráfico radar - OWASP TOP 10 (CORREGIDO PARA EVITAR OVERFLOW)
function initRadarChart() {
    // VERIFICAR SI EL ELEMENTO EXISTS ANTES DE OBTENER EL CONTEXTO
    const radarElement = document.getElementById('radarChart');
    if (!radarElement) {
        console.log('Elemento radarChart no encontrado - puede estar oculto');
        return; // Salir si no existe el elemento
    }
    
    let radarCtx;
    try {
        radarCtx = radarElement.getContext('2d');
    } catch (error) {
        console.error('Error al obtener contexto del canvas:', error);
        return;
    }
    
    // DATOS CON VALIDACIÓN MEJORADA
    const owaspData = window.dashboardData?.owaspData || {
        labels: ['A01: Broken Access Control', 'A02: Cryptographic Failures', 'A03: Injection', 'A04: Insecure Design', 'A05: Security Misconfiguration', 'A06: Vulnerable Components', 'A07: Auth Failures', 'A08: Data Integrity', 'A09: Logging Failures', 'A10: SSRF'],
        data: [8, 6, 7, 4, 5, 3, 6, 5, 4, 3]
    };
    
    // VALIDAR QUE LOS DATOS SEAN ARRAYS
    if (!Array.isArray(owaspData.labels) || !Array.isArray(owaspData.data)) {
        console.error('Datos OWASP inválidos');
        return;
    }
    
    try {
        new Chart(radarCtx, {
            type: 'radar',
            data: {
                labels: owaspData.labels,
                datasets: [{
                    label: 'OWASP TOP 10',
                    data: owaspData.data,
                    fill: true,
                    backgroundColor: 'rgba(0, 48, 89, 0.2)',
                    borderColor: '#003059',
                    borderWidth: 2,
                    pointBackgroundColor: '#FF2778',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointHoverBackgroundColor: '#ffffff',
                    pointHoverBorderColor: '#FF2778'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, // CAMBIO: false para mejor control
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: '#1a1f2e',
                        titleColor: '#ffffff',
                        bodyColor: '#a0aec0',
                        borderColor: '#FF2778',
                        borderWidth: 1,
                        callbacks: {
                            // MEJORAR TOOLTIPS
                            title: function(context) {
                                return context[0].label;
                            },
                            label: function(context) {
                                return `Vulnerabilidades: ${context.parsed.r}`;
                            }
                        }
                    }
                },
                scales: {
                    r: {
                        angleLines: { 
                            color: "rgba(255, 255, 255, 0.3)",
                            lineWidth: 1
                        },
                        grid: { 
                            color: "rgba(255, 255, 255, 0.2)",
                            lineWidth: 1
                        },
                        pointLabels: { 
                            color: "#ffffff",
                            font: { 
                                size: 10, // Reducir más para evitar overflow
                                weight: '500'
                            },
                            padding: 15, // Aumentar padding para evitar cortes
                            // NUEVO: Callback para acortar etiquetas largas
                            callback: function(label) {
                                if (label.length > 15) {
                                    return label.substring(0, 12) + '...';
                                }
                                return label;
                            }
                        },
                        ticks: { 
                            color: "#ffffff",
                            backdropColor: "transparent", 
                            font: { size: 9 },
                            stepSize: 2,
                            showLabelBackdrop: false,
                            display: true // ASEGURAR QUE SE MUESTREN
                        },
                        max: Math.max(...owaspData.data) + 2, // DINÁMICO basado en datos
                        min: 0,
                        beginAtZero: true
                    }
                },
                layout: {
                    padding: {
                        top: 25,    // AUMENTAR padding
                        right: 25,
                        bottom: 25,
                        left: 25
                    }
                },
                // NUEVO: Configuración adicional para evitar errores
                animation: {
                    duration: 1000
                },
                interaction: {
                    intersect: false,
                    mode: 'nearest'
                }
            }
        });
        
        console.log('Gráfico radar inicializado correctamente');
        
    } catch (error) {
        console.error('Error al crear el gráfico radar:', error);
        
        // FALLBACK: mostrar mensaje de error en el contenedor
        const container = radarElement.parentElement;
        if (container) {
            container.innerHTML = `
                <div class="chart-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Error al cargar gráfico OWASP</p>
                </div>
            `;
        }
    }
}

// Gráfico de progreso (donut)
let progressChart;

function initProgressChart() {
    const progressElement = document.getElementById('scanProgressChart');
    if (!progressElement) {
        console.log('Canvas scanProgressChart no encontrado, saltando inicialización');
        return;
    }
    
    const progressCtx = progressElement.getContext('2d');
    
    progressChart = new Chart(progressCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ["#FF2778", "#2d3748"],
                borderWidth: 0,
                cutout: '85%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
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
                
                const fontSize = Math.min(width, height) / 8;
                ctx.font = `bold ${fontSize}px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`;
                ctx.textBaseline = "middle";
                ctx.textAlign = "center";
                ctx.fillStyle = "#a0aec0";
                
                const text = chart.data.datasets[0].data[0] + "%";
                ctx.fillText(text, width / 2, height / 2);
                
                ctx.save();
            }
        }]
    });
}

// Monitoreo de progreso
function startProgressMonitoring() {
    updateProgress();
    setInterval(updateProgress, 30000);
}

// Actualizar progreso del scanner (CORREGIDO PARA TU ENDPOINT)
function updateProgress() {
    $.ajax({
        url: '/scan_progress',
        type: 'GET',
        dataType: 'json',
        timeout: 10000,
        success: function(data) {
            console.log('Datos del scanner recibidos:', data);
            
            // Actualizar gráfico de progreso
            if (progressChart && data.progress !== undefined) {
                progressChart.data.datasets[0].data = [data.progress, 100 - data.progress];
                progressChart.update('none');
            }
            
            // Actualizar información del scanner
            updateScannerInfo(data);
            updateMetrics(data);
            
            // Si se completó un escaneo, actualizar alertas
            if (data.justCompleted) {
                showToast('¡Escaneo completado exitosamente!', 'success');
                setTimeout(loadLastScanAlerts, 2000);
            }
        },
        error: function(xhr, status, error) {
            console.error('Error al obtener progreso del scanner:', error);
            
            // En caso de error, mostrar información de error
            updateScannerStatus('error');
            updateMetrics({ activeScans: 0, scheduledScans: 0 });
        }
    });
}

// Actualizar información del scanner (CORREGIDO)
function updateScannerInfo(data) {
    const ultimoElement = document.getElementById('ultimoScanner');
    const proximoElement = document.getElementById('proximoScanner');
    const fechaElement = document.getElementById('proximoScannerFecha');
    
    if (ultimoElement) {
        ultimoElement.textContent = data.ultimoScanner || 'Sin escaneos recientes';
    }
    
    if (proximoElement) {
        proximoElement.textContent = data.proximo || 'No programado';
    }
    
    if (fechaElement) {
        fechaElement.textContent = data.fecha || '';
    }
    
    // Actualizar estado del scanner basado en el progreso
    const statusElement = document.getElementById('scannerStatus');
    if (!statusElement) return;
    
    const indicator = statusElement.querySelector('.status-indicator');
    const statusText = statusElement.querySelector('span');
    
    if (!indicator || !statusText) return;
    
    if (data.progress > 0 && data.progress < 100) {
        indicator.className = 'status-indicator active';
        statusText.textContent = 'Escaneando';
    } else if (data.progress === 100) {
        indicator.className = 'status-indicator';
        statusText.textContent = 'Completado';
    } else {
        indicator.className = 'status-indicator';
        statusText.textContent = 'En espera';
    }
}

// Actualizar métricas (CORREGIDO)
function updateMetrics(data) {
    const activeScanElement = document.getElementById('activeScans');
    const scheduledScanElement = document.getElementById('scheduledScans');
    
    if (activeScanElement && data.activeScans !== undefined) {
        activeScanElement.textContent = data.activeScans;
    }
    
    if (scheduledScanElement && data.scheduledScans !== undefined) {
        scheduledScanElement.textContent = data.scheduledScans;
    }
}

// Actualizar estado del scanner
function updateScannerStatus(status) {
    const statusElement = document.getElementById('scannerStatus');
    if (!statusElement) return;
    
    const indicator = statusElement.querySelector('.status-indicator');
    const text = statusElement.querySelector('span');
    
    if (!indicator || !text) return;
    
    switch(status) {
        case 'active':
            indicator.className = 'status-indicator active';
            text.textContent = 'Activo';
            break;
        case 'scanning':
            indicator.className = 'status-indicator active';
            text.textContent = 'Escaneando';
            break;
        case 'error':
            indicator.className = 'status-indicator error';
            text.textContent = 'Error';
            break;
        default:
            indicator.className = 'status-indicator';
            text.textContent = 'En espera';
    }
}

// Gestión de botones de período
$(document).on('click', '.chart-btn', function() {
    const period = $(this).data('period');
    
    $('.chart-btn').removeClass('active');
    $(this).addClass('active');
    
    console.log('Período seleccionado:', period);
});

// Función para mostrar toasts
function showToast(message, type = 'info') {
    const iconClass = type === 'success' ? 'fa-check-circle text-success' : 
                     type === 'error' ? 'fa-exclamation-triangle text-danger' : 
                     'fa-info-circle text-info';
    
    const toastMessage = document.getElementById('toastMessage');
    if (toastMessage) {
        toastMessage.innerHTML = `<i class="fas ${iconClass} me-2"></i>${message}`;
        
        const toastElement = document.getElementById('dashboardToast');
        if (toastElement && typeof bootstrap !== 'undefined') {
            const toast = new bootstrap.Toast(toastElement);
            toast.show();
        }
    }
}

// Inicializar tooltips
function initializeTooltips() {
    if (typeof bootstrap === 'undefined') return;
    
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            theme: 'dark'
        });
    });
}

// Función para actualizar datos de gráficos (placeholder)
function updateChartData(period) {
    showToast(`Actualizando datos para período: ${period}`, 'info');
}
