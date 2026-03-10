/* WaaS Self-Service Portal - Application JavaScript */

document.addEventListener('DOMContentLoaded', function () {

    // Auto-dismiss flash alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    });

    // -------------------------------------------------------
    // Confirmation Modal (Task A)
    // Intercept form submit when form has data-confirm-message
    // -------------------------------------------------------
    const confirmModal = document.getElementById('confirmModal');
    if (confirmModal) {
        const modalInstance = new bootstrap.Modal(confirmModal);
        const modalBody = document.getElementById('confirmModalBody');
        const modalBtn = document.getElementById('confirmModalBtn');
        let pendingForm = null;

        document.querySelectorAll('form[data-confirm-message]').forEach(function (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                pendingForm = form;
                modalBody.textContent = form.getAttribute('data-confirm-message');
                modalInstance.show();
            });
        });

        // Also handle button-level data-confirm (for non-form elements)
        document.querySelectorAll('[data-confirm]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                const form = el.closest('form');
                if (form) {
                    e.preventDefault();
                    pendingForm = form;
                    modalBody.textContent = el.getAttribute('data-confirm');
                    modalInstance.show();
                }
            });
        });

        modalBtn.addEventListener('click', function () {
            if (pendingForm) {
                // Remove the data-confirm-message temporarily so re-submit doesn't loop
                const msg = pendingForm.getAttribute('data-confirm-message');
                pendingForm.removeAttribute('data-confirm-message');
                pendingForm.submit();
                if (msg) pendingForm.setAttribute('data-confirm-message', msg);
                pendingForm = null;
            }
            modalInstance.hide();
        });

        confirmModal.addEventListener('hidden.bs.modal', function () {
            pendingForm = null;
        });
    }

    // -------------------------------------------------------
    // Client-Side Form Validation (Task C)
    // Bootstrap "was-validated" pattern for .needs-validation
    // -------------------------------------------------------
    document.querySelectorAll('form.needs-validation').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // -------------------------------------------------------
    // Client-Side Search/Filter on Lists (Task D)
    // -------------------------------------------------------
    document.querySelectorAll('[data-search-target]').forEach(function (input) {
        var tbodyId = input.getAttribute('data-search-target');
        var tbody = document.getElementById(tbodyId);
        var countEl = input.closest('.search-filter-wrapper') ?
            input.closest('.search-filter-wrapper').querySelector('.search-count') : null;
        if (!tbody) return;

        var rows = tbody.querySelectorAll('tr');
        var totalRows = rows.length;

        input.addEventListener('input', function () {
            var query = input.value.toLowerCase().trim();
            var visibleCount = 0;
            rows.forEach(function (row) {
                var text = row.textContent.toLowerCase();
                if (!query || text.indexOf(query) !== -1) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            if (countEl) {
                if (query) {
                    var msg = (window.i18n && window.i18n.showing_x_of_y)
                        ? window.i18n.showing_x_of_y.replace('%(visible)s', visibleCount).replace('%(total)s', totalRows)
                        : 'Showing ' + visibleCount + ' of ' + totalRows;
                    countEl.textContent = msg;
                    countEl.style.display = '';
                } else {
                    countEl.style.display = 'none';
                }
            }
        });
    });

    // -------------------------------------------------------
    // Session Timeout Warning (Task E)
    // -------------------------------------------------------
    var isAuthenticated = document.body.getAttribute('data-authenticated') === 'true';
    if (isAuthenticated) {
        var WARNING_MS = 28 * 60 * 1000;   // 28 minutes
        var LOGOUT_MS = 30 * 60 * 1000;    // 30 minutes
        var warningTimer, logoutTimer;
        var sessionWarningModal = document.getElementById('sessionWarningModal');
        var sessionModalInstance = sessionWarningModal ? new bootstrap.Modal(sessionWarningModal) : null;

        function resetSessionTimers() {
            clearTimeout(warningTimer);
            clearTimeout(logoutTimer);
            warningTimer = setTimeout(showSessionWarning, WARNING_MS);
            logoutTimer = setTimeout(doSessionLogout, LOGOUT_MS);
        }

        function showSessionWarning() {
            if (sessionModalInstance) {
                sessionModalInstance.show();
            }
        }

        function doSessionLogout() {
            window.location.href = '/auth/logout';
        }

        function keepAlive() {
            fetch('/auth/keepalive', { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function () { resetSessionTimers(); })
                .catch(function () {});
            if (sessionModalInstance) sessionModalInstance.hide();
        }

        // Continue Session button
        var continueBtn = document.getElementById('sessionContinueBtn');
        if (continueBtn) {
            continueBtn.addEventListener('click', keepAlive);
        }

        // Reset timers on user activity
        ['click', 'keypress', 'mousemove', 'scroll'].forEach(function (evt) {
            document.addEventListener(evt, function () {
                resetSessionTimers();
            }, { passive: true });
        });

        resetSessionTimers();
    }

    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (el) {
        return new bootstrap.Tooltip(el);
    });

    // Active nav link highlighting
    var currentPath = window.location.pathname;
    document.querySelectorAll('.navbar-nav .nav-link').forEach(function (link) {
        var href = link.getAttribute('href');
        if (href && currentPath.startsWith(href) && href !== '/') {
            link.classList.add('active');
        } else if (href === '/' && currentPath === '/') {
            link.classList.add('active');
        }
    });

    console.log('WaaS Portal initialized.');
});
