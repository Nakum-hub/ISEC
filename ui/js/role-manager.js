// Role Management System
// Handles user role display, switching, and permission updates globally

function getIsecBridge() {
    if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
        return null;
    }
    return window.isec;
}

const RoleManager = {
    init() {
        this.bindEvents();
        this.startAutoRefresh();
    },

    bindEvents() {
        const switchBtn = document.getElementById('switch-role-btn');
        if (switchBtn) {
            switchBtn.addEventListener('click', () => this.switchRole());
        }

        // Listen for backend status updates if we add an event emitter later
        // For now, we rely on the interval
    },

    startAutoRefresh() {
        this.refreshStatus();
        setInterval(() => this.refreshStatus(), 15000);
    },

    async refreshStatus() {
        try {
            const bridge = getIsecBridge();
            if (!bridge) return;

            const status = await bridge.invoke('get-backend-status');
            if (status) {
                this.updateUI(status);

                // Also update dashboard permission UI if it exists globally
                if (typeof updatePermissionUI === 'function') {
                    updatePermissionUI(status);
                }
            }
        } catch (e) {
            console.error('Role refresh failed', e);
        }
    },

    updateUI(status) {
        const roleLabel = document.getElementById('current-role-label');
        const roleSelect = document.getElementById('role-select');
        const switchBtn = document.getElementById('switch-role-btn');
        const userAvatar = document.querySelector('.user-avatar');

        if (!status) return;

        const currentRole = status.role || 'unknown';

        // Update Label
        if (roleLabel) {
            roleLabel.textContent = currentRole;
        }

        // Update Select
        if (roleSelect && roleSelect.value !== currentRole && ['collector', 'reviewer', 'exporter'].includes(currentRole)) {
            roleSelect.value = currentRole;
        }

        // Update Button State
        if (switchBtn) {
            if (status.tamperingDetected) {
                switchBtn.disabled = true;
                switchBtn.title = 'Role switching blocked: Tampering Detected';
            } else {
                switchBtn.disabled = false;
                switchBtn.title = 'Switch to selected role';
            }
        }

        // Update Avatar Ring Color based on role
        if (userAvatar) {
            userAvatar.setAttribute('data-role', currentRole);
        }
    },

    async switchRole() {
        const bridge = getIsecBridge();
        if (!bridge) {
            alert('Role switching unavailable.');
            return;
        }

        const roleSelect = document.getElementById('role-select');
        if (!roleSelect) return;

        const targetRole = String(roleSelect.value || '').toLowerCase();

        const confirmSwitch = confirm(`Authenticate as '${targetRole}'? \n\nThis action will be logged in the secure audit trail.`);
        if (!confirmSwitch) return;

        try {
            const result = await bridge.invoke('set-user-role', targetRole);

            if (result && result.success) {
                if (result.status) {
                    this.updateUI(result.status);
                    if (typeof loadDashboardStats === 'function') loadDashboardStats();
                }
                // Success feedback
                const btn = document.getElementById('switch-role-btn');
                const originalText = btn.innerHTML;
                btn.innerHTML = '✓';
                setTimeout(() => btn.innerHTML = originalText, 2000);
            } else {
                alert('Role switch failed: ' + (result?.message || 'Unknown error'));
            }
        } catch (error) {
            console.error('Role switch error:', error);
            alert('System Error: ' + error.message);
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    RoleManager.init();
});
