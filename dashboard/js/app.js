/**
 * PQC Zero-Trust Mesh - Observability & Security Dashboard Engine
 * Handles real-time telemetry processing, genuine OPA policy evaluations,
 * Vault PKI lifecycle coordination, topology animations, and test suites.
 */

// Application State
const state = {
  events: [],
  filteredEvents: [],
  activeTab: 'overview',
  refreshInterval: null,
  certVersionCounter: 2,
  caSerial: '406c95b2a5e4b6c810d7',
  activeCertificates: [
    {
      service: 'frontend',
      uri: 'spiffe://pqzt.local/ns/demo/sa/frontend',
      version: 2,
      serial: '810445f6d92d4159dc70d74d13ad5aff3bdc6b7',
      rotationType: 'scheduled_rotation',
      status: 'ACTIVE',
      validFrom: new Date(Date.now() - 3600000).toISOString(),
      validUntil: new Date(Date.now() + 43200000).toISOString(),
      details: 'Vault PKI issued version 2 certificate for frontend (Envoy SDS)'
    },
    {
      service: 'backend',
      uri: 'spiffe://pqzt.local/ns/demo/sa/backend',
      version: 2,
      serial: '3a7b1d600a9561b49f93b00fae7d6d76782b789d',
      rotationType: 'scheduled_rotation',
      status: 'ACTIVE',
      validFrom: new Date(Date.now() - 3600000).toISOString(),
      validUntil: new Date(Date.now() + 43200000).toISOString(),
      details: 'Vault PKI issued version 2 certificate for backend (Hot-swapped)'
    }
  ],
  selectedEventJson: null
};

// ==============================================================================
// Initialization
// ==============================================================================
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupSimulationControls();
  setupFilters();
  setupModals();
  loadTelemetryData();

  // Auto-refresh every 4 seconds
  state.refreshInterval = setInterval(() => {
    loadTelemetryData(false);
  }, 4000);
});

// ==============================================================================
// Navigation & Tab Switching
// ==============================================================================
function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const tabId = item.getAttribute('data-tab');
      switchTab(tabId);
    });
  });

  const refreshBtn = document.getElementById('btn-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      loadTelemetryData(true);
      showToast('Telemetry Synced', 'Audit events reloaded successfully', 'success');
    });
  }
}

function switchTab(tabId) {
  state.activeTab = tabId;

  // Update sidebar active class
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.getAttribute('data-tab') === tabId);
  });

  // Update tab panel visibility
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === `panel-${tabId}`);
  });
}

// ==============================================================================
// Telemetry Data Loading & KPI Calculation
// ==============================================================================
async function loadTelemetryData(showNotice = false) {
  try {
    let events = [];

    // First try relative API endpoint
    try {
      const resp = await fetch('/api/events');
      if (resp.ok) {
        const data = await resp.json();
        events = Array.isArray(data) ? data : (data.events || []);
      }
    } catch (e) {
      // Fallback: direct relative read from opa telemetry folder
      const fallbackResp = await fetch('../opa/telemetry/audit_log.json');
      if (fallbackResp.ok) {
        events = await fallbackResp.json();
      }
    }

    // Fetch live runtime component status (OPA CLI + Vault engine mode + CA serial)
    try {
      const statusResp = await fetch('/api/status');
      if (statusResp.ok) {
        const statusData = await statusResp.json();
        updateRuntimeStatusPills(statusData);
      }
    } catch (e) {
      // Ignore if opened statically without backend server
    }

    if (events && events.length > 0) {
      state.events = events;
      updateKPIs();
      renderMiniStream();
      renderAuthorizationsTable();
      renderCertificatesTable();
      renderEventsTable();
      if (showNotice) {
        showToast('Telemetry Updated', `Synced ${events.length} audit records`, 'success');
      }
    }
  } catch (err) {
    console.warn('Telemetry fetch error:', err);
  }
}

function updateRuntimeStatusPills(statusData) {
  if (!statusData) return;
  if (statusData.ca_serial) {
    state.caSerial = statusData.ca_serial;
    const elCaSerial = document.getElementById('ca-serial');
    if (elCaSerial) elCaSerial.textContent = state.caSerial;
  }

  const elMeshLabel = document.getElementById('mesh-health-pill-label');
  if (elMeshLabel) {
    elMeshLabel.textContent = statusData.opa_installed
      ? 'Mesh: OPA CLI Live (ext_authz)'
      : 'Mesh: Policy Fallback Mode';
  }

  const elVaultLabel = document.getElementById('vault-pki-pill-label');
  if (elVaultLabel) {
    elVaultLabel.textContent = statusData.live_vault_healthy
      ? 'Vault PKI: Live API (pki_mesh)'
      : 'Vault PKI: Emulation (pki_mesh)';
  }
}

function updateKPIs() {
  const events = state.events;

  // 1. Total & Authz Decisions
  const authzEvents = events.filter(e => e.category === 'authorization' || e.eventType === 'allowed_request' || e.eventType === 'denied_request');
  const allowed = authzEvents.filter(e => e.decision === true || e.eventType === 'allowed_request').length;
  const denied = authzEvents.filter(e => e.decision === false || e.eventType === 'denied_request').length;
  const totalAuthz = allowed + denied;

  // 2. Crypto Rotations & Revocations
  const rotationEvents = events.filter(e => e.eventType === 'key_certificate_rotation');
  const rotations = rotationEvents.filter(e => e.rotationType === 'scheduled_rotation' || e.rotationType === 'initial_issuance').length;
  const revocations = rotationEvents.filter(e => e.status === 'REVOKED' || e.rotationType === 'emergency_revocation').length;

  // 3. Genuine vs Simulated breakdown
  const genuineCount = events.filter(e => e.isGenuine === true).length;
  const genuinePct = events.length > 0 ? Math.round((genuineCount / events.length) * 100) : 100;

  // Update DOM Elements
  const elTotal = document.getElementById('val-total-requests');
  const elAllowed = document.getElementById('val-allowed-requests');
  const elAllowedPct = document.getElementById('badge-allowed-pct');
  const elDenied = document.getElementById('val-denied-requests');
  const elRotations = document.getElementById('val-rotations');
  const elRevocations = document.getElementById('val-revocations');

  if (elTotal) elTotal.textContent = totalAuthz;
  if (elAllowed) elAllowed.textContent = allowed;
  if (elAllowedPct) {
    const pct = totalAuthz > 0 ? Math.round((allowed / totalAuthz) * 100) : 100;
    elAllowedPct.textContent = `${pct}% Rate`;
  }
  if (elDenied) elDenied.textContent = denied;
  if (elRotations) elRotations.textContent = rotations;
  if (elRevocations) elRevocations.textContent = revocations;

  // Update Provenance Pill in header
  const elProvPill = document.getElementById('val-provenance-pill');
  if (elProvPill) {
    elProvPill.textContent = `Telemetry: ${genuinePct}% Genuine (${genuineCount}/${events.length})`;
  }

  // Update SDS metrics
  const elSdsActive = document.getElementById('sds-active-leafs');
  const elSdsRenewals = document.getElementById('sds-renewals');
  const elSdsRevoked = document.getElementById('sds-revoked');
  const elCaSerial = document.getElementById('ca-serial');

  const revokedSerials = new Set(
    rotationEvents
      .filter(e => e.status === 'REVOKED' || e.rotationType === 'emergency_revocation')
      .map(e => e.serialNumber)
      .filter(Boolean)
  );
  const activeSerials = new Set(
    rotationEvents
      .filter(e => e.status === 'SUCCESS' && e.serialNumber && !revokedSerials.has(e.serialNumber))
      .map(e => e.serialNumber)
  );

  if (elSdsActive) elSdsActive.textContent = activeSerials.size || state.activeCertificates.length;
  if (elSdsRenewals) elSdsRenewals.textContent = rotations;
  if (elSdsRevoked) elSdsRevoked.textContent = revocations;
  if (elCaSerial) elCaSerial.textContent = state.caSerial;
}

// ==============================================================================
// Mini Stream (Overview Tab)
// ==============================================================================
function renderMiniStream() {
  const container = document.getElementById('mini-event-stream');
  if (!container) return;

  const recent = [...state.events].reverse().slice(0, 10);
  if (recent.length === 0) {
    container.innerHTML = '<div class="empty-state-loading">No telemetry events recorded yet.</div>';
    return;
  }

  container.innerHTML = recent.map((e, idx) => {
    const timeStr = formatTimestamp(e.timestamp);
    const sev = e.severity || 'INFO';
    const type = formatEventType(e.eventType);
    const identity = e.sourceIdentity || e.serviceIdentity || e.clientIp || 'Unknown';
    const desc = e.reason || e.details || e.failureReason || 'Action logged';
    const provBadge = e.isGenuine ? '<span class="badge genuine" style="font-size:9px; padding:1px 4px;">GENUINE</span>' : '<span class="badge simulated" style="font-size:9px; padding:1px 4px;">SIMULATED</span>';

    return `
      <div class="mini-event-card severity-${sev}" onclick="viewEventDetails(${state.events.length - 1 - idx})">
        <div class="mini-event-header">
          <span class="mini-event-type">${type}</span>
          <div style="display:flex; align-items:center; gap:6px;">
            ${provBadge}
            <span class="mini-event-time">${timeStr}</span>
          </div>
        </div>
        <div class="mini-event-identity" title="${escapeHtml(identity)}">${escapeHtml(identity)}</div>
        <div class="mini-event-desc">${escapeHtml(desc)}</div>
      </div>
    `;
  }).join('');
}

// ==============================================================================
// Authorizations Table (ext_authz Tab)
// ==============================================================================
function renderAuthorizationsTable() {
  const tbody = document.getElementById('tbody-authorizations');
  if (!tbody) return;

  const authzEvents = state.events.filter(e => 
    e.category === 'authorization' || e.eventType === 'allowed_request' || e.eventType === 'denied_request'
  ).reverse();

  const query = (document.getElementById('authz-search')?.value || '').toLowerCase();
  const filtered = authzEvents.filter(e => {
    if (!query) return true;
    const s = `${e.sourceIdentity} ${e.destinationService} ${e.path} ${e.reason}`.toLowerCase();
    return s.includes(query);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state-loading">No matching authorization decisions found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(e => {
    const isAllow = e.decision === true || e.eventType === 'allowed_request';
    const badgeClass = isAllow ? 'success' : 'danger';
    const badgeText = isAllow ? 'ALLOW' : 'DENY';
    const action = e.action || 'GET';
    const path = e.path || '/';
    const provBadge = e.isGenuine ? '<span class="badge genuine">GENUINE</span>' : '<span class="badge simulated">SIMULATED</span>';

    return `
      <tr>
        <td class="font-mono">${formatTimestamp(e.timestamp)}</td>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="font-mono text-cyan">${escapeHtml(e.sourceIdentity || 'unknown')}</td>
        <td><strong>${escapeHtml(e.destinationService || 'backend')}</strong></td>
        <td><span class="badge neutral">${escapeHtml(action)}</span></td>
        <td class="font-mono">${escapeHtml(path)}</td>
        <td>${escapeHtml(e.reason || 'OPA Policy Evaluation')}</td>
        <td>${provBadge}</td>
      </tr>
    `;
  }).join('');
}

// ==============================================================================
// Certificates Table (Vault PKI Tab)
// ==============================================================================
function renderCertificatesTable() {
  const tbody = document.getElementById('tbody-certificates');
  if (!tbody) return;

  const certEvents = state.events.filter(e => e.eventType === 'key_certificate_rotation').reverse();

  if (certEvents.length === 0) {
    tbody.innerHTML = state.activeCertificates.map(c => `
      <tr>
        <td><strong>${escapeHtml(c.service)}</strong></td>
        <td class="font-mono text-cyan">${escapeHtml(c.uri)}</td>
        <td><span class="badge purple">V${c.version}</span></td>
        <td class="font-mono text-dim">${c.serial.slice(0, 16)}...</td>
        <td><span class="badge neutral">${c.rotationType}</span></td>
        <td><span class="badge success">${c.status}</span></td>
        <td class="font-mono" style="font-size: 11px;">12h Short-Lived</td>
        <td>${escapeHtml(c.details)}</td>
      </tr>
    `).join('');
    return;
  }

  tbody.innerHTML = certEvents.map(e => {
    const service = e.serviceIdentity && e.serviceIdentity.includes('backend') ? 'backend' : 'frontend';
    const isRevoked = e.status === 'REVOKED';
    const statusBadge = isRevoked ? '<span class="badge danger">REVOKED (CRL)</span>' : '<span class="badge success">ACTIVE</span>';
    const ver = e.version ? `V${e.version}` : (isRevoked ? 'V1' : 'V2');
    const serial = e.serialNumber ? `${e.serialNumber.slice(0, 16)}...` : '--';

    return `
      <tr>
        <td><strong>${escapeHtml(service)}</strong></td>
        <td class="font-mono text-cyan">${escapeHtml(e.serviceIdentity || '--')}</td>
        <td><span class="badge purple">${ver}</span></td>
        <td class="font-mono text-dim" title="${escapeHtml(e.serialNumber || '')}">${serial}</td>
        <td><span class="badge neutral">${escapeHtml(e.rotationType || 'scheduled')}</span></td>
        <td>${statusBadge}</td>
        <td class="font-mono" style="font-size: 11px;">12h Short-Lived</td>
        <td>${escapeHtml(e.details || '')}</td>
      </tr>
    `;
  }).join('');
}

// ==============================================================================
// Full Audit Events Table (Audit Stream Tab)
// ==============================================================================
function renderEventsTable() {
  const tbody = document.getElementById('tbody-events');
  if (!tbody) return;

  const categoryFilter = document.getElementById('filter-event-category')?.value || 'all';
  const severityFilter = document.getElementById('filter-severity')?.value || 'all';
  const sourceFilter = document.getElementById('filter-event-source')?.value || 'all';
  const query = (document.getElementById('events-search')?.value || '').toLowerCase();

  const allEvents = state.events.map((e, origIdx) => ({ ...e, _origIdx: origIdx })).reverse();
  const filtered = allEvents.filter(e => {
    if (categoryFilter !== 'all' && e.category !== categoryFilter) return false;
    if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
    if (sourceFilter === 'genuine' && e.isGenuine !== true) return false;
    if (sourceFilter === 'simulated' && e.isGenuine === true) return false;
    if (query) {
      const match = `${e.eventType} ${e.sourceIdentity} ${e.serviceIdentity} ${e.reason} ${e.details}`.toLowerCase();
      if (!match.includes(query)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state-loading">No events match the selected filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(e => {
    const sev = e.severity || 'INFO';
    const sevClass = sev === 'CRITICAL' ? 'danger' : (sev === 'HIGH' ? 'danger' : (sev === 'WARNING' ? 'warning' : 'success'));
    const identity = e.sourceIdentity || e.serviceIdentity || e.clientIp || '--';
    const decision = e.decision !== undefined ? (e.decision ? '<span class="badge success">ALLOW</span>' : '<span class="badge danger">DENY</span>') : (e.status ? `<span class="badge purple">${e.status}</span>` : '--');
    const desc = e.reason || e.details || e.failureReason || '--';
    const provBadge = e.isGenuine ? '<span class="badge genuine">GENUINE</span>' : '<span class="badge simulated">SIMULATED</span>';

    return `
      <tr>
        <td class="font-mono">${formatTimestamp(e.timestamp)}</td>
        <td>${provBadge}</td>
        <td><span class="badge ${sevClass}">${sev}</span></td>
        <td><span class="badge neutral">${escapeHtml(e.category || 'general')}</span></td>
        <td><strong>${formatEventType(e.eventType)}</strong></td>
        <td class="font-mono text-cyan" title="${escapeHtml(identity)}">${escapeHtml(identity.length > 35 ? identity.slice(0, 35) + '...' : identity)}</td>
        <td>${decision}</td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(desc)}">${escapeHtml(desc)}</td>
        <td>
          <button class="btn btn-sm btn-outline" onclick="viewEventDetails(${e._origIdx})">JSON</button>
        </td>
      </tr>
    `;
  }).join('');
}

// ==============================================================================
// Interactive Simulations & Particle Animations
// ==============================================================================
function setupSimulationControls() {
  // 1. Authorized Request
  document.getElementById('btn-sim-allow')?.addEventListener('click', () => {
    animatePacket('path-fe-be', '#10b981');
    fetch('/api/evaluate-opa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        caller_identity: 'spiffe://pqzt.local/ns/demo/sa/frontend',
        destination: 'backend',
        action: 'GET',
        path: '/api/v1/resource'
      })
    })
    .then(r => r.json())
    .then(data => {
      loadTelemetryData(false);
      showToast('Authorized Request Verified', `Genuine OPA Decision: ALLOW (${data.reason}) [${data.eval_duration_ms}ms]`, 'success');
    })
    .catch(() => {
      const fallbackEvent = {
        timestamp: new Date().toISOString(),
        eventType: 'allowed_request',
        category: 'authorization',
        severity: 'INFO',
        sourceIdentity: 'spiffe://pqzt.local/ns/demo/sa/frontend',
        destinationService: 'backend',
        action: 'GET',
        path: '/api/v1/resource',
        decision: true,
        isGenuine: false,
        reason: 'Access granted: approved frontend identity'
      };
      pushEvent(fallbackEvent);
      showToast('Authorized Request Sent', 'OPA ext_authz evaluated: ALLOW (200 OK)', 'success');
    });
  });

  // 2. Lateral Movement to Database (Denied)
  document.getElementById('btn-sim-lateral')?.addEventListener('click', () => {
    animatePacket('path-fe-db', '#f43f5e');
    fetch('/api/evaluate-opa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        caller_identity: 'spiffe://pqzt.local/ns/demo/sa/frontend',
        destination: 'database',
        action: 'GET',
        path: '/database/credentials'
      })
    })
    .then(r => r.json())
    .then(data => {
      loadTelemetryData(false);
      showToast('Lateral Movement Blocked', `Genuine OPA Decision: DENY (${data.reason}) [${data.eval_duration_ms}ms]`, 'danger');
    })
    .catch(() => {
      const fallbackEvent = {
        timestamp: new Date().toISOString(),
        eventType: 'denied_request',
        category: 'authorization',
        severity: 'WARNING',
        sourceIdentity: 'spiffe://pqzt.local/ns/demo/sa/frontend',
        destinationService: 'database',
        action: 'GET',
        path: '/database/credentials',
        decision: false,
        isGenuine: false,
        reason: 'Access denied: lateral movement to database prevented'
      };
      pushEvent(fallbackEvent);
      showToast('Lateral Movement Blocked', 'Access denied to microsegmented database (403 Forbidden)', 'danger');
    });
  });

  // 3. Rogue Attacker Workload SVID (Denied)
  document.getElementById('btn-sim-rogue')?.addEventListener('click', () => {
    animatePacket('path-attacker-be', '#f43f5e');
    fetch('/api/evaluate-opa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        caller_identity: 'spiffe://pqzt.local/ns/demo/sa/unapproved-attacker',
        destination: 'backend',
        action: 'GET',
        path: '/api/v1/resource'
      })
    })
    .then(r => r.json())
    .then(data => {
      loadTelemetryData(false);
      showToast('Rogue SVID Rejected', `Genuine OPA Decision: DENY (${data.reason}) [${data.eval_duration_ms}ms]`, 'danger');
    })
    .catch(() => {
      const fallbackEvent = {
        timestamp: new Date().toISOString(),
        eventType: 'denied_request',
        category: 'authorization',
        severity: 'WARNING',
        sourceIdentity: 'spiffe://pqzt.local/ns/demo/sa/unapproved-attacker',
        destinationService: 'backend',
        action: 'GET',
        path: '/api/v1/resource',
        decision: false,
        isGenuine: false,
        reason: 'Access denied: unapproved identity or unauthorized destination'
      };
      pushEvent(fallbackEvent);
      showToast('Rogue SVID Rejected', 'OPA blocked unapproved workload identity (403 Forbidden)', 'danger');
    });
  });

  // 4. Dynamic Certificate Rotation (Vault SDS)
  document.getElementById('btn-sim-rotate')?.addEventListener('click', () => {
    animatePacket('path-vault-sds', '#8b5cf6');
    fetch('/api/vault/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ common_name: 'frontend', is_server: false })
    })
    .then(r => r.json())
    .then(data => {
      loadTelemetryData(false);
      showToast('Certificate Rotated', `Vault PKI issued version ${data.version} certificate (${data.backend})`, 'warning');
    })
    .catch(() => {
      state.certVersionCounter += 1;
      const v = state.certVersionCounter;
      const newSerial = Array.from({length: 40}, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const fallbackEvent = {
        timestamp: new Date().toISOString(),
        eventType: 'key_certificate_rotation',
        category: 'crypto_lifecycle',
        severity: 'INFO',
        serviceIdentity: 'spiffe://pqzt.local/ns/demo/sa/frontend',
        rotationType: 'scheduled_rotation',
        algorithm: 'Hybrid ECDH-P256 + ML-KEM-768',
        serialNumber: newSerial,
        version: v,
        status: 'SUCCESS',
        isGenuine: false,
        details: `Vault PKI dynamically rotated certificate to Version ${v} (Envoy SDS Hot-Swap)`
      };
      pushEvent(fallbackEvent);
      showToast('Certificate Rotated', `Vault PKI issued V${v} leaf cert without downtime`, 'warning');
    });
  });

  // 5. Emergency Certificate Revocation (CRL)
  document.getElementById('btn-sim-revoke')?.addEventListener('click', () => {
    fetch('/api/vault/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    })
    .then(r => r.json())
    .then(data => {
      loadTelemetryData(false);
      showToast('Serial Revoked', `Emergency revocation registered in Vault CRL (${data.serial})`, 'warning');
    })
    .catch(() => {
      const revokedSerial = Array.from({length: 40}, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const fallbackEvent = {
        timestamp: new Date().toISOString(),
        eventType: 'key_certificate_rotation',
        category: 'crypto_lifecycle',
        severity: 'WARNING',
        serviceIdentity: 'spiffe://pqzt.local/ns/demo/sa/frontend',
        rotationType: 'emergency_revocation',
        algorithm: 'Hybrid ECDH-P256 + ML-KEM-768',
        serialNumber: revokedSerial,
        status: 'REVOKED',
        isGenuine: false,
        details: 'Emergency CRL revocation enforced in Vault (simulated_key_compromise)'
      };
      pushEvent(fallbackEvent);
      showToast('Serial Revoked', 'Emergency revocation registered in Vault CRL', 'warning');
    });
  });
}

function pushEvent(event) {
  state.events.push(event);
  updateKPIs();
  renderMiniStream();
  renderAuthorizationsTable();
  renderCertificatesTable();
  renderEventsTable();

  // Send to backend if server is running
  fetch('/api/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(event)
  }).catch(() => {});
}

// SVG Packet Animation
function animatePacket(pathId, color) {
  const path = document.getElementById(pathId);
  const svg = document.getElementById('mesh-svg-canvas');
  if (!path || !svg) return;

  const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  circle.setAttribute('r', '6');
  circle.setAttribute('fill', color);
  circle.style.filter = 'drop-shadow(0 0 6px ' + color + ')';
  svg.appendChild(circle);

  const length = path.getTotalLength();
  const duration = 1200; // ms
  const startTime = performance.now();

  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const point = path.getPointAtLength(progress * length);
    circle.setAttribute('cx', point.x);
    circle.setAttribute('cy', point.y);

    if (progress < 1) {
      requestAnimationFrame(step);
    } else {
      svg.removeChild(circle);
    }
  }

  requestAnimationFrame(step);
}

// ==============================================================================
// Modals & Test Execution
// ==============================================================================
function setupModals() {
  // Event JSON modal
  const jsonModal = document.getElementById('modal-json-backdrop');
  document.getElementById('btn-close-modal')?.addEventListener('click', () => {
    jsonModal.style.display = 'none';
  });
  document.getElementById('btn-close-modal-footer')?.addEventListener('click', () => {
    jsonModal.style.display = 'none';
  });

  document.getElementById('btn-copy-json')?.addEventListener('click', () => {
    if (state.selectedEventJson) {
      navigator.clipboard.writeText(JSON.stringify(state.selectedEventJson, null, 2)).then(() => {
        showToast('Copied', 'JSON payload copied to clipboard', 'success');
      });
    }
  });

  // Tests Runner modal
  const testsModal = document.getElementById('modal-tests-backdrop');
  document.getElementById('btn-run-tests-modal')?.addEventListener('click', () => {
    testsModal.style.display = 'flex';
  });
  document.getElementById('btn-close-tests-modal')?.addEventListener('click', () => {
    testsModal.style.display = 'none';
  });
  document.getElementById('btn-close-tests-modal-footer')?.addEventListener('click', () => {
    testsModal.style.display = 'none';
  });

  // Run OPA Policy Suite (28 Tests)
  document.getElementById('btn-exec-opa-tests')?.addEventListener('click', () => {
    runSuite('opa');
  });

  // Run Service Request Path Suite (15 Tests)
  document.getElementById('btn-exec-service-tests')?.addEventListener('click', () => {
    runSuite('service_path');
  });

  // Run Vault PKI & Rotation Suite (14 Tests)
  document.getElementById('btn-exec-vault-tests')?.addEventListener('click', () => {
    runSuite('vault_pki');
  });

  // Run Dashboard Runtime Telemetry Suite (4 Tests)
  document.getElementById('btn-exec-dashboard-tests')?.addEventListener('click', () => {
    runSuite('dashboard');
  });
}

async function runSuite(suiteName) {
  const outputEl = document.getElementById('test-terminal-output');
  if (!outputEl) return;

  outputEl.textContent = `[+] Initiating automated test suite: ${suiteName}...\n[+] Running child process inside workspace...\n`;

  try {
    const resp = await fetch('/api/run-tests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ suite: suiteName })
    });

    if (resp.ok) {
      const res = await resp.json();
      outputEl.textContent = res.output;
      if (res.exit_code === 0) {
        showToast('Tests Passed', `${suiteName} suite completed with 100% pass rate`, 'success');
        loadTelemetryData(false);
      } else {
        showToast('Tests Failed', `${suiteName} suite exited with code ${res.exit_code}`, 'danger');
      }
    } else {
      outputEl.textContent += `[-] Server responded with error ${resp.status}: ${resp.statusText}\n`;
    }
  } catch (err) {
    outputEl.textContent += `[-] Failed triggering suite: ${err.message}\n`;
  }
}

function viewEventDetails(eventIndex) {
  const event = state.events[eventIndex];
  if (!event) return;

  state.selectedEventJson = event;
  const modal = document.getElementById('modal-json-backdrop');
  const codeEl = document.getElementById('modal-json-content')?.querySelector('code');

  if (codeEl && modal) {
    codeEl.textContent = JSON.stringify(event, null, 2);
    modal.style.display = 'flex';
  }
}

function setupFilters() {
  document.getElementById('authz-search')?.addEventListener('input', renderAuthorizationsTable);
  document.getElementById('filter-event-category')?.addEventListener('change', renderEventsTable);
  document.getElementById('filter-severity')?.addEventListener('change', renderEventsTable);
  document.getElementById('filter-event-source')?.addEventListener('change', renderEventsTable);
  document.getElementById('events-search')?.addEventListener('input', renderEventsTable);
}

// ==============================================================================
// Toast Notifications & Helpers
// ==============================================================================
function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) {
    const div = document.createElement('div');
    div.id = 'toast-container';
    div.className = 'toast-container';
    document.body.appendChild(div);
  }

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type}`;
  toast.innerHTML = `
    <div class="toast-title">${escapeHtml(title)}</div>
    <div class="toast-msg">${escapeHtml(message)}</div>
  `;

  document.getElementById('toast-container').appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatTimestamp(isoStr) {
  if (!isoStr) return '--';
  try {
    const d = new Date(isoStr);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  } catch {
    return isoStr;
  }
}

function formatEventType(type) {
  if (!type) return 'Event';
  return type
    .replace(/_/g, ' ')
    .replace(/\b\w/g, l => l.toUpperCase());
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
