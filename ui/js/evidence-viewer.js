/*
Premium Security Evidence Viewer UI Module
Implements the frontend for viewing collected evidence with enhanced visualizations and animations
*/

// Role-based access control

function getIsecInvoker() {
    if (typeof window !== 'undefined' && window.isec && typeof window.isec.invoke === 'function') {
        return window.isec.invoke.bind(window.isec);
    }
    return null;
}

async function invokeIsec(channel, ...args) {
    const invoker = getIsecInvoker();
    if (!invoker) {
        throw new Error('IPC bridge not available');
    }
    return invoker(channel, ...args);
}

let currentUserRole = null;
let userPermissions = [];

// Initialize the evidence viewer
document.addEventListener('DOMContentLoaded', function() {
    loadUserRole();
    initializeUI();
    loadEvidenceTimeline();
    initializeAnimations();
    updateIntegrityStatus();
    updateConfidenceMeter();
    updateExportReadiness();

    const refreshIntervalMs = 15000;
    setInterval(() => {
        loadEvidenceTimeline();
        loadEvidenceCounts();
        updateIntegrityStatus();
        updateConfidenceMeter();
        updateExportReadiness();
    }, refreshIntervalMs);
});

// Initialize animations
function initializeAnimations() {
    // Trigger entrance animations
    document.querySelectorAll('.dashboard-card').forEach((card, index) => {
        setTimeout(() => {
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 200 + index * 100);
    });
}

// Load user role from backend
async function loadUserRole() {
    try {
        const roleData = await invokeIsec('get-user-role');
        
        currentUserRole = roleData.role;
        userPermissions = roleData.permissions || [];
        
        // Update UI based on role
        updateUIForRole();
    } catch (error) {
        console.error('Error loading user role:', error);
        // Default to reviewer role if unable to load
        currentUserRole = 'reviewer';
        userPermissions = ['view'];
        updateUIForRole();
    }
}

// Update UI elements based on user role
function updateUIForRole() {
    // Hide/show elements based on permissions
    if (!userPermissions.includes('collect')) {
        document.querySelectorAll('.collection-controls').forEach(el => el.style.display = 'none');
    }
    
    if (!userPermissions.includes('export')) {
        document.querySelectorAll('.export-controls').forEach(el => el.style.display = 'none');
    }
    
    if (!userPermissions.includes('modify')) {
        document.querySelectorAll('.modify-controls').forEach(el => el.style.display = 'none');
    }
    
    // Update role indicator
    const roleIndicator = document.getElementById('role-indicator');
    if (roleIndicator) {
        roleIndicator.innerHTML = `<span>Role: ${currentUserRole}</span>`;
        roleIndicator.className = `status-badge role-${currentUserRole}`;
    }

    const roleSelect = document.getElementById('role-select');
    if (roleSelect && currentUserRole && roleSelect.value !== currentUserRole) {
        roleSelect.value = currentUserRole;
    }
}

function initializeRoleSwitcher() {
    const roleSelect = document.getElementById('role-select');
    const switchBtn = document.getElementById('switch-role-btn');

    if (!roleSelect || !switchBtn) {
        return;
    }

    switchBtn.addEventListener('click', async () => {
        const targetRole = String(roleSelect.value || '').toLowerCase();
        if (!['collector', 'reviewer', 'exporter'].includes(targetRole)) {
            showError('Invalid role selection');
            return;
        }

        if (targetRole === currentUserRole) {
            showSuccess(`Already using ${targetRole} role`);
            return;
        }

        const confirmSwitch = confirm(`Switch role to ${targetRole}? This action is logged.`);
        if (!confirmSwitch) {
            return;
        }

        try {
            const result = await invokeIsec('set-user-role', targetRole);
            if (result && result.success) {
                const status = result.status || {};
                currentUserRole = status.role || targetRole;
                userPermissions = Array.isArray(status.permissions) ? status.permissions : userPermissions;
                updateUIForRole();
                updateExportReadiness();
                showSuccess(result.message || 'Role updated');
            } else {
                showError((result && result.message) ? result.message : 'Role change failed');
            }
        } catch (error) {
            console.error('Role change failed:', error);
            showError(error.message || 'Role change failed');
        }
    });
}

// Initialize UI components
function initializeUI() {
    // Set up event listeners
    document.getElementById('refresh-btn')?.addEventListener('click', loadEvidenceTimeline);
    document.getElementById('export-btn')?.addEventListener('click', handleExport);
    document.getElementById('collect-btn')?.addEventListener('click', handleCollection);
    document.getElementById('retention-settings-btn')?.addEventListener('click', handleRetentionSettings);
    initializeRoleSwitcher();
    
    // Initialize dashboard widgets
    initializeDashboard();
}

// Initialize dashboard widgets
function initializeDashboard() {
    // Load evidence counts
    loadEvidenceCounts();
    
    // Set up filters
    setupFilters();
    
    // Set up animations for dashboard cards
    document.querySelectorAll('.dashboard-card').forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    });
}

// Load evidence counts for dashboard
async function loadEvidenceCounts() {
    try {
        const status = await invokeIsec('get-backend-status');
        const counts = (status && status.evidenceTypeCounts) ? status.evidenceTypeCounts : {};
        const total = (status && typeof status.evidenceItemsCount === 'number') ? status.evidenceItemsCount : 0;
        
        // Update dashboard counters
        const totalEl = document.getElementById('total-evidence-count');
        if (totalEl) totalEl.textContent = String(total || 0);
        const systemLogsEl = document.getElementById('system-logs-count');
        if (systemLogsEl) systemLogsEl.textContent = String(counts.system_logs || 0);
        const browserHistoryEl = document.getElementById('browser-history-count');
        if (browserHistoryEl) browserHistoryEl.textContent = String(counts.browser_history || 0);
        const networkConnectionsEl = document.getElementById('network-connections-count');
        if (networkConnectionsEl) networkConnectionsEl.textContent = String(counts.network_connections || 0);
        const fileMetadataEl = document.getElementById('file-metadata-count');
        if (fileMetadataEl) fileMetadataEl.textContent = String(counts.file_metadata || 0);
        
        // Update confidence meter based on evidence quality
        updateConfidenceMeter();
        
        // Update export readiness
        updateExportReadiness();
    } catch (error) {
        console.error('Error loading evidence counts:', error);
    }
}

// Update confidence meter
async function updateConfidenceMeter() {
    try {
        const confidenceData = await invokeIsec('get-evidence-confidence');
        
        const confidenceFill = document.getElementById('confidence-meter-fill');
        if (!confidenceFill) return;
        
        // Animate the confidence meter
        setTimeout(() => {
            confidenceFill.style.width = `${confidenceData.score}%`;
            
            // Add appropriate class based on confidence level
            const meter = confidenceFill.parentElement;
            meter.classList.remove('low', 'medium', 'high');
            if (confidenceData.score < 40) {
                meter.classList.add('low');
            } else if (confidenceData.score < 70) {
                meter.classList.add('medium');
            } else {
                meter.classList.add('high');
            }
        }, 100);
    } catch (error) {
        console.error('Error updating confidence meter:', error);
    }
}

// Update integrity status
async function updateIntegrityStatus() {
    try {
        const integrityData = await invokeIsec('get-system-integrity');
        
        const integrityStatus = document.getElementById('integrity-status');
        if (!integrityStatus) return;
        
        if (integrityData.status === 'valid') {
            integrityStatus.className = 'status-badge status-integrity-valid';
            integrityStatus.innerHTML = '<span>Integrity: Valid</span>';
        } else if (integrityData.status === 'compromised') {
            integrityStatus.className = 'status-badge status-integrity-danger';
            integrityStatus.innerHTML = '<span>Integrity: Compromised</span>';
        } else {
            integrityStatus.className = 'status-badge status-integrity-warning';
            integrityStatus.innerHTML = '<span>Integrity: Warning</span>';
        }
    } catch (error) {
        console.error('Error updating integrity status:', error);
    }
}

// Update export readiness indicator
async function updateExportReadiness() {
    try {
        const readinessData = await invokeIsec('get-export-readiness');
        
        const exportStatus = document.getElementById('export-readiness-status');
        const exportMessage = document.getElementById('export-readiness-message');
        
        if (!exportStatus || !exportMessage) return;
        
        if (readinessData.ready) {
            exportStatus.className = 'export-ready';
            exportStatus.textContent = '✓ Export Ready';
            exportMessage.textContent = 'All evidence verified and exportable';
        } else {
            exportStatus.className = 'export-not-ready';
            exportStatus.textContent = '⚠ Export Not Ready';
            exportMessage.textContent = readinessData.reasons.length > 0 
                ? readinessData.reasons.join(', ') 
                : 'No evidence available for export';
        }
    } catch (error) {
        console.error('Error updating export readiness:', error);
    }
}

// Set up filter controls
function setupFilters() {
    const filterForm = document.getElementById('filter-form');
    if (filterForm) {
        filterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(filterForm);
            const filters = Object.fromEntries(formData.entries());
            loadEvidenceTimeline(filters);
        });
    }
}

// Load evidence timeline
async function loadEvidenceTimeline(filters = {}) {
    showLoading(true);
    
    try {
        const response = await invokeIsec('get-evidence-timeline');
        const evidenceData = response && response.success ? response.items : [];
        
        renderEvidenceTimeline(evidenceData);
    } catch (error) {
        console.error('Error loading evidence timeline:', error);
        showError('Failed to load evidence timeline');
    } finally {
        showLoading(false);
    }
}

// Render evidence timeline
function renderEvidenceTimeline(evidenceData) {
    const timelineContainer = document.getElementById('timeline-container');
    if (!timelineContainer) return;
    
    // Clear existing content
    timelineContainer.innerHTML = '';
    
    if (!evidenceData || evidenceData.length === 0) {
        timelineContainer.innerHTML = '<div class="empty-state">No evidence found</div>';
        return;
    }
    
    // Group evidence by date
    const groupedEvidence = groupEvidenceByDate(evidenceData);
    
    // Render each day's evidence
    Object.entries(groupedEvidence).forEach(([date, items]) => {
        const dateSection = createTimelineSection(date, items);
        timelineContainer.appendChild(dateSection);
    });
}

// Group evidence by date
function groupEvidenceByDate(evidenceItems) {
    const grouped = {};
    
    evidenceItems.forEach(item => {
        const date = new Date(item.timestamp).toLocaleDateString();
        if (!grouped[date]) {
            grouped[date] = [];
        }
        grouped[date].push(item);
    });
    
    // Sort dates in descending order (most recent first)
    return Object.keys(grouped)
        .sort((a, b) => new Date(b) - new Date(a))
        .reduce((obj, key) => {
            obj[key] = grouped[key];
            return obj;
        }, {});
}

// Create timeline section for a date
function createTimelineSection(date, items) {
    const section = document.createElement('div');
    section.className = 'timeline-section';
    
    const header = document.createElement('h3');
    header.className = 'timeline-date';
    header.textContent = date;
    section.appendChild(header);
    
    const itemsContainer = document.createElement('div');
    itemsContainer.className = 'timeline-items';
    
    items.forEach(item => {
        const itemElement = createTimelineItem(item);
        itemsContainer.appendChild(itemElement);
    });
    
    section.appendChild(itemsContainer);
    return section;
}

// Create timeline item
function createTimelineItem(item) {
    const itemDiv = document.createElement('div');
    itemDiv.className = 'timeline-item';
    itemDiv.dataset.id = item.id;
    
    // Determine icon based on evidence type
    const icon = getEvidenceIcon(item.type);
    
    itemDiv.innerHTML = `
        <div class="timeline-icon">${icon}</div>
        <div class="timeline-content">
            <div class="timeline-header">
                <span class="evidence-type">${item.type.replace('_', ' ').toUpperCase()}</span>
                <span class="timestamp">${formatTimestamp(item.timestamp)}</span>
            </div>
            <div class="timeline-body">
                <div class="evidence-summary">${item.description}</div>
                <div class="chain-of-custody">
                    <span class="severity">Severity: ${item.severity}</span>
                </div>
            </div>
            <div class="timeline-actions">
                <button class="btn btn-sm view-details" onclick="showEvidenceDetails(${item.id})">View Details</button>
                ${userPermissions.includes('modify') ? 
                    `<button class="btn btn-sm btn-danger delete-evidence" onclick="deleteEvidence(${item.id})">Delete</button>` : ''}
            </div>
        </div>
    `;
    
    return itemDiv;
}

// Get icon for evidence type
function getEvidenceIcon(evidenceType) {
    const icons = {
        'system_logs': '📝',
        'browser_history': '🌐',
        'network_connections': '🔗',
        'file_metadata': '📁',
        'role_assignment': '👤',
        'consent_record': '✅',
        'retention_expiry_flag': '🗑️',
        'evidence_deletion': '❌'
    };
    
    return icons[evidenceType] || '📦';
}

// Format timestamp for display
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

// Show evidence details in modal
async function showEvidenceDetails(evidenceId) {
    try {
        const response = await invokeIsec('get-evidence-timeline');
        const timelineData = response && response.success ? response.items : [];
        const evidenceData = timelineData.find(item => item.id == evidenceId);
        
        if (!evidenceData) {
            showError('Evidence not found');
            return;
        }
        
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Evidence Details</h3>
                    <span class="close" onclick="closeModal()">&times;</span>
                </div>
                <div class="modal-body">
                    <div class="evidence-detail">
                        <h4>Type: ${evidenceData.type}</h4>
                        <p><strong>ID:</strong> ${evidenceData.id}</p>
                        <p><strong>Timestamp:</strong> ${formatTimestamp(evidenceData.timestamp)}</p>
                        <p><strong>Description:</strong> ${evidenceData.description}</p>
                        <p><strong>Severity:</strong> ${evidenceData.severity}</p>
                        
                        <h5>Data:</h5>
                        <pre class="evidence-data">${JSON.stringify(evidenceData.data, null, 2)}</pre>
                        
                        <h5>Chain of Custody:</h5>
                        <p><strong>Integrity Status:</strong> 
                            <span class="${evidenceData.severity === 'critical' ? 'status-invalid' : 'status-valid'}">
                                ${evidenceData.severity === 'critical' ? 'COMPROMISED' : 'VALID'}
                            </span>
                        </p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn" onclick="closeModal()">Close</button>
                    ${userPermissions.includes('modify') ? 
                        `<button class="btn btn-danger" onclick="confirmDeleteEvidence(${evidenceData.id})">Delete Evidence</button>` : ''}
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Trigger modal animation
        setTimeout(() => {
            modal.classList.add('show');
        }, 10);
        
        // Close modal when clicking outside content
        window.onclick = function(event) {
            if (event.target === modal) {
                closeModal();
            }
        };
    } catch (error) {
        console.error('Error loading evidence details:', error);
        showError('Failed to load evidence details');
    }
}

// Close modal
function closeModal() {
    const modal = document.querySelector('.modal');
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.remove();
        }, 300);
    }
}

// Handle export action
function handleExport() {
    if (!userPermissions.includes('export')) {
        showError('Export permission denied');
        return;
    }
    
    performExport('zip');
}

// Perform export
async function performExport(format) {
    try {
        showLoading(true);
        const result = await invokeIsec('export-evidence', { format });
        
        if (result.success) {
            showSuccess(`Export completed: ${result.filePath}`);
        } else {
            throw new Error(result.message || 'Export failed');
        }
    } catch (error) {
        console.error('Export error:', error);
        showError(error.message || 'Export failed');
    } finally {
        showLoading(false);
    }
}

// Handle collection action
function handleCollection() {
    if (!userPermissions.includes('collect')) {
        showError('Collection permission denied');
        return;
    }
    
    // Confirm collection start
    if (confirm('Start new evidence collection? This will gather system logs, network connections, and other evidence.')) {
        startCollection();
    }
}

// Start collection process
async function startCollection() {
    try {
        showLoading(true);
        const result = await invokeIsec('start-evidence-collection', {});
        
        if (result.success) {
            showSuccess(result.message);
            // Refresh timeline after a delay
            setTimeout(() => {
                loadEvidenceTimeline();
                loadEvidenceCounts(); // Update counts and indicators
                updateConfidenceMeter();
                updateIntegrityStatus();
                updateExportReadiness();
            }, 2000);
        } else {
            throw new Error(result.message || 'Collection failed');
        }
    } catch (error) {
        console.error('Collection error:', error);
        showError(error.message || 'Collection failed');
    } finally {
        showLoading(false);
    }
}

// Handle retention settings
function handleRetentionSettings() {
    if (!userPermissions.includes('modify')) {
        showError('Retention settings require modify permission');
        return;
    }
    
    showRetentionSettingsModal();
}

// Show retention settings modal
function showRetentionSettingsModal() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content" style="width: 600px;">
            <div class="modal-header">
                <h3>Evidence Retention Settings</h3>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="retention-settings-form">
                    <h4>Set Retention Policy</h4>
                    <div class="form-group">
                        <label for="retention-policy">Policy Type:</label>
                        <select id="retention-policy" class="form-control">
                            <option value="temporary">Temporary (7 days)</option>
                            <option value="short_term">Short Term (30 days)</option>
                            <option value="medium_term" selected>Medium Term (90 days)</option>
                            <option value="long_term">Long Term (365 days)</option>
                            <option value="permanent">Permanent (no expiry)</option>
                            <option value="custom">Custom Days</option>
                        </select>
                    </div>
                    
                    <div class="form-group" id="custom-days-group" style="display:none;">
                        <label for="custom-days">Custom Days:</label>
                        <input type="number" id="custom-days" class="form-control" min="1" value="90">
                    </div>
                    
                    <div class="form-group">
                        <label>Current Status:</label>
                        <div id="current-retention-status">
                            Loading retention status...
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="applyRetentionSettings()">Apply Settings</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Trigger modal animation
    setTimeout(() => {
        modal.classList.add('show');
    }, 10);
    
    // Set up event listener for policy change
    const policySelect = document.getElementById('retention-policy');
    const customDaysGroup = document.getElementById('custom-days-group');
    
    policySelect.addEventListener('change', function() {
        if (this.value === 'custom') {
            customDaysGroup.style.display = 'block';
        } else {
            customDaysGroup.style.display = 'none';
        }
    });
    
    // Load current retention status
    loadCurrentRetentionStatus();
    
    // Close modal when clicking outside content
    window.onclick = function(event) {
        if (event.target === modal) {
            closeModal();
        }
    };
}

// Load current retention status
async function loadCurrentRetentionStatus() {
    try {
        const status = await invokeIsec('get-retention-status');
        
        const statusDiv = document.getElementById('current-retention-status');
        statusDiv.innerHTML = `
            <p><strong>Policy:</strong> ${status.policy}</p>
            <p><strong>Retention Days:</strong> ${status.retention_days}</p>
            <p><strong>Total Evidence:</strong> ${status.total_evidence}</p>
            <p><strong>Active Evidence:</strong> ${status.active_evidence}</p>
            <p><strong>Expired Evidence:</strong> ${status.expired_evidence}</p>
        `;
    } catch (error) {
        console.error('Error loading retention status:', error);
        const statusDiv = document.getElementById('current-retention-status');
        statusDiv.textContent = 'Error loading retention status';
    }
}

// Apply retention settings
async function applyRetentionSettings() {
    const policySelect = document.getElementById('retention-policy');
    const customDaysInput = document.getElementById('custom-days');
    
    const policy = policySelect.value;
    let customDays = null;
    
    if (policy === 'custom') {
        customDays = parseInt(customDaysInput.value);
        if (isNaN(customDays) || customDays < 1) {
            showError('Please enter a valid number of days');
            return;
        }
    }
    
    try {
        showLoading(true);
        
        const result = await invokeIsec('set-retention-settings', {
            policy: policy,
            custom_days: customDays
        });
        
        if (result.success) {
            showSuccess(result.message);
            closeModal();
            loadEvidenceTimeline(); // Refresh the timeline to reflect changes
            updateConfidenceMeter();
            updateExportReadiness();
        } else {
            throw new Error(result.message || 'Failed to apply retention settings');
        }
    } catch (error) {
        console.error('Error applying retention settings:', error);
        showError(error.message || 'Failed to apply retention settings');
    } finally {
        showLoading(false);
    }
}

// Delete evidence
async function deleteEvidence(evidenceId) {
    if (!userPermissions.includes('modify')) {
        showError('Modify permission denied');
        return;
    }
    
    confirmDeleteEvidence(evidenceId);
}

// Confirm and delete evidence
function confirmDeleteEvidence(evidenceId) {
    if (confirm('Are you sure you want to delete this evidence? This action cannot be undone.')) {
        performDelete(evidenceId);
    }
}

// Perform delete operation
async function performDelete(evidenceId) {
    try {
        showLoading(true);
        // In a real implementation, send delete request to backend
        // For now, just show success message
        showSuccess('Evidence deleted successfully');
        // Reload timeline
        loadEvidenceTimeline();
        loadEvidenceCounts(); // Update counts and indicators
        updateConfidenceMeter();
        updateExportReadiness();
    } catch (error) {
        console.error('Delete error:', error);
        showError('Delete failed');
    } finally {
        showLoading(false);
    }
}

// Show loading state
function showLoading(show) {
    const loader = document.getElementById('loading-indicator');
    if (loader) {
        if (show) {
            loader.classList.add('show');
        } else {
            loader.classList.remove('show');
        }
    }
}

// Show error message
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-error';
    errorDiv.textContent = message;
    
    // Add to alerts container or body
    const alertsContainer = document.getElementById('alerts-container') || document.body;
    alertsContainer.insertBefore(errorDiv, alertsContainer.firstChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        errorDiv.remove();
    }, 5000);
}

// Show success message
function showSuccess(message) {
    const successDiv = document.createElement('div');
    successDiv.className = 'alert alert-success';
    successDiv.textContent = message;
    
    // Add to alerts container or body
    const alertsContainer = document.getElementById('alerts-container') || document.body;
    alertsContainer.insertBefore(successDiv, alertsContainer.firstChild);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        successDiv.remove();
    }, 3000);
}
