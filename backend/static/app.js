/**
 * SecureWatch Frontend Application Logic
 * Real-time polling, interactive controls, blockchain tamper testing,
 * scenario injection, and threat analytics.
 */

const API_BASE = "";
let currentTab = "threat-monitor";
let isSimRunning = false;
let autoRefreshInterval = null;

// DOM Elements
const statTotal = document.getElementById("statTotal");
const statSafe = document.getElementById("statSafe");
const statUnverified = document.getElementById("statUnverified");
const statSuspicious = document.getElementById("statSuspicious");
const statAttacks = document.getElementById("statAttacks");
const statQuarantined = document.getElementById("statQuarantined");
const statBlocks = document.getElementById("statBlocks");
const devicesTableBody = document.getElementById("devicesTableBody");
const ledgerBlocksContainer = document.getElementById("ledgerBlocksContainer");
const eventsTableBody = document.getElementById("eventsTableBody");
const btnToggleSim = document.getElementById("btnToggleSim");
const systemStatusText = document.getElementById("systemStatusText");
const deviceSearchInput = document.getElementById("deviceSearchInput");
const deviceStatusFilter = document.getElementById("deviceStatusFilter");
const toastContainer = document.getElementById("toastContainer");
const deviceModal = document.getElementById("deviceModal");
const btnCloseModal = document.getElementById("btnCloseModal");
const deviceCountBadge = document.getElementById("deviceCountBadge");

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initEventListeners();
  fetchStats();
  fetchDevices();
  fetchLedger();
  fetchEvents();
  fetchModelMetrics();
  fetchSimStatus();

  // Polling every 2.5 seconds
  autoRefreshInterval = setInterval(() => {
    fetchStats();
    if (currentTab === "threat-monitor") fetchDevices();
    if (currentTab === "blockchain-ledger") fetchLedger();
    if (currentTab === "event-log") fetchEvents();
  }, 2500);
});

// --- Tab Switching ---
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const target = tab.getAttribute("data-tab");
      currentTab = target;

      document.querySelectorAll(".tab-pane").forEach(pane => {
        pane.style.display = "none";
      });

      const activePane = document.getElementById(`tab-${target}`);
      if (activePane) activePane.style.display = "block";

      // Refresh tab specific data
      if (target === "threat-monitor") fetchDevices();
      if (target === "blockchain-ledger") fetchLedger();
      if (target === "event-log") fetchEvents();
      if (target === "ai-inspector") fetchModelMetrics();
    });
  });
}

// --- Event Listeners ---
function initEventListeners() {
  document.getElementById("btnRefreshDevices")?.addEventListener("click", fetchDevices);
  deviceSearchInput?.addEventListener("input", fetchDevices);
  deviceStatusFilter?.addEventListener("change", fetchDevices);

  btnToggleSim?.addEventListener("click", toggleSimulationStream);
  
  document.getElementById("btnVerifyLedger")?.addEventListener("click", () => verifyLedger(false));
  document.getElementById("btnTamperTest")?.addEventListener("click", triggerTamperTest);
  document.getElementById("btnTamperReset")?.addEventListener("click", resetTamperTest);
  
  document.getElementById("btnLearnEnv")?.addEventListener("click", async () => {
    const btn = document.getElementById("btnLearnEnv");
    if (btn) btn.disabled = true;
    showToast("🧭 Learning Environment: Scanning ambient devices for 15 seconds...", "info");
    
    let remaining = 15;
    const countdown = setInterval(() => {
      remaining--;
      if (btn && remaining > 0) {
        btn.innerHTML = `<span>⏳</span> Learning (${remaining}s)`;
      }
    }, 1000);

    setTimeout(async () => {
      clearInterval(countdown);
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span>🧭</span> Learn Environment`;
      }
      try {
        const res = await fetch(`${API_BASE}/api/v1/system/learn-environment`, { method: "POST" });
        if (res.ok) {
          const data = await res.json();
          showToast(`✅ Baseline Established: ${data.learned_devices} ambient devices registered as known nominal baseline.`, "success");
          fetchStats();
          fetchDevices();
        }
      } catch (err) {
        console.error("Learn environment error:", err);
      }
    }, 15000);
  });

  document.getElementById("btnClearData")?.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to clear all devices, events, and the trusted whitelist? (The blockchain audit ledger will remain intact)")) {
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/v1/system/clear-data`, { method: "POST" });
      if (res.ok) {
        showToast("All devices, events, and trusted devices cleared! Audit ledger preserved.", "success");
        fetchStats();
        fetchDevices();
        fetchEvents();
      }
    } catch (err) {
      console.error("Failed to clear system data:", err);
    }
  });

  document.getElementById("btnResetLedger")?.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to reset the cryptographic audit ledger back to the Genesis block?")) {
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/v1/ledger/reset`, { method: "POST" });
      if (res.ok) {
        showToast("Audit ledger successfully reset to Genesis block.", "success");
        fetchStats();
        fetchLedger();
      }
    } catch (err) {
      console.error("Failed to reset ledger:", err);
    }
  });

  btnCloseModal?.addEventListener("click", () => {
    deviceModal.style.display = "none";
  });

  window.addEventListener("click", (e) => {
    if (e.target === deviceModal) {
      deviceModal.style.display = "none";
    }
  });
}

// --- Fetch System Stats ---
async function fetchStats() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/stats`);
    if (!res.ok) return;
    const data = await res.json();

    statTotal.textContent = data.devices.total;
    statSafe.textContent = data.devices.safe;
    if (statUnverified && data.devices.unverified !== undefined) {
      statUnverified.textContent = data.devices.unverified;
    }
    statSuspicious.textContent = data.devices.suspicious;
    statAttacks.textContent = data.devices.attacks;
    statQuarantined.textContent = data.devices.quarantined;
    statBlocks.textContent = data.ledger.total_blocks;

    isSimRunning = data.simulation.running;
    updateSimButtonUI(isSimRunning);
  } catch (err) {
    console.error("Failed to fetch stats:", err);
  }
}

// --- Fetch Tracked Devices ---
async function fetchDevices() {
  try {
    const search = deviceSearchInput.value.trim();
    const status = deviceStatusFilter.value;
    let url = `${API_BASE}/api/v1/devices?limit=200`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;

    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();

    // Update device count badge
    const deviceList = data.devices || [];
    if (deviceCountBadge) {
      deviceCountBadge.textContent = `${data.count || deviceList.length} device${deviceList.length !== 1 ? 's' : ''} tracked`;
    }

    renderDevicesTable(deviceList);
  } catch (err) {
    console.error("Failed to fetch devices:", err);
  }
}

function renderDevicesTable(devices) {
  if (!devices || devices.length === 0) {
    devicesTableBody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align:center; padding: 2rem; color: var(--text-muted);">
          No devices match current filter.
        </td>
      </tr>
    `;
    return;
  }

  devicesTableBody.innerHTML = devices.map(dev => {
    const statusClass = (dev.status || "SAFE").toLowerCase();
    const isQuarantined = Boolean(dev.quarantined || dev.blocked);
    const isTrusted = Boolean(dev.trusted);
    const rep = Math.round(dev.reputation || 0);
    const repColor = rep > 70 ? "var(--status-safe)" : rep > 40 ? "var(--status-suspicious)" : "var(--status-attack)";
    const statusTooltip = dev.status === "UNVERIFIED" ? 'title="Identity hidden or unrecognised. No malicious behaviour observed."' : '';

    // Brand display
    const brand = dev.brand || null;
    const howIdentified = dev.how_identified || '';
    const brandDisplay = brand
      ? `<span style="font-weight: 600; color: #e2e8f0;" title="${escapeHtml(howIdentified)}">${escapeHtml(brand)}</span>`
      : `<span style="color: var(--text-muted); font-size: 0.78rem; cursor: help;" title="Device hides its name and vendor for privacy">Unidentified</span>`;

    // Device type display with icon
    const deviceTypeStr = dev.device_type_str || null;
    const deviceTypeIcon = dev.device_type_icon || '📶';
    const typeDisplay = deviceTypeStr
      ? `<span title="${escapeHtml(deviceTypeStr)}">${deviceTypeIcon} ${escapeHtml(deviceTypeStr)}</span>`
      : `<span style="color: var(--text-muted);">—</span>`;

    // MAC type badge
    const macType = dev.mac_type || 'unknown';
    const macTypeLabel = dev.mac_type_label || 'Unknown';
    const macTypeColor = dev.mac_type_color || '#6b7280';
    const macTypeBadge = `<span class="mac-type-badge" style="background: ${macTypeColor}20; color: ${macTypeColor}; border: 1px solid ${macTypeColor}40; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.62rem; font-weight: 600; white-space: nowrap; margin-left: 0.3rem;" title="MAC type: ${macTypeLabel}. ${macType === 'public' ? 'OUI prefix usable for vendor lookup.' : 'Randomized — OUI prefix is not reliable for identification.'}">${macTypeLabel}</span>`;

    return `
      <tr>
        <td>
          <span class="badge badge-${statusClass}" ${statusTooltip}>
            ${dev.status === "UNVERIFIED" ? "🔍 UNVERIFIED" : dev.status}
          </span>
          ${isTrusted ? '<span class="badge badge-trusted" style="margin-left: 4px;">🛡️ TRUSTED</span>' : ''}
          ${isQuarantined ? '<span class="badge badge-quarantined" style="margin-left: 4px;">QUARANTINED</span>' : ''}
        </td>
        <td>
          <strong style="cursor:pointer; color: #38bdf8;" onclick="inspectDevice('${dev.device_id}')">
            ${escapeHtml(dev.device_name || "Unknown")}
          </strong>
        </td>
        <td>${brandDisplay}</td>
        <td style="font-size: 0.82rem;">${typeDisplay}</td>
        <td>
          <span class="mac-code">${escapeHtml(dev.device_id)}</span>
          ${macTypeBadge}
        </td>
        <td><span style="font-family: var(--font-mono);">${dev.rssi || "-"} dBm</span></td>
        <td>
          <span style="font-weight: 700; color: ${dev.risk_score > 40 ? 'var(--status-attack)' : dev.risk_score > 15 ? 'var(--status-suspicious)' : 'var(--status-safe)'}">
            ${Math.round(dev.risk_score || 0)}
          </span>
        </td>
        <td>
          <div class="reputation-bar-wrapper">
            <span style="font-family: var(--font-mono); font-size: 0.75rem; width: 28px;">${rep}</span>
            <div class="reputation-bar">
              <div class="reputation-fill" style="width: ${rep}%; background: ${repColor};"></div>
            </div>
          </div>
        </td>
        <td>
          <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
            <button class="btn btn-outline btn-sm" onclick="inspectDevice('${dev.device_id}')">Inspect</button>
            ${isTrusted
              ? `<button class="btn btn-untrust btn-sm" onclick="toggleTrustDevice('${dev.device_id}', false)" title="Remove from trusted whitelist config">Untrust</button>`
              : `<button class="btn btn-trust btn-sm" onclick="toggleTrustDevice('${dev.device_id}', true)" title="Save to config and mark as SAFE">★ Trust</button>`
            }
            ${isQuarantined 
              ? `<button class="btn btn-success btn-sm" onclick="unblockDevice('${dev.device_id}')">Unblock</button>`
              : `<button class="btn btn-danger btn-sm" onclick="quarantineDevice('${dev.device_id}')">Quarantine</button>`
            }
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

// --- Device Details Modal ---
async function inspectDevice(deviceId) {
  try {
    const res = await fetch(`${API_BASE}/api/v1/devices/${deviceId}`);
    if (!res.ok) return;
    const data = await res.json();
    const dev = data.device;
    const rssiHistory = data.rssi_history || [];
    const isTrusted = Boolean(dev.trusted);

    document.getElementById("modalDeviceName").textContent = `Inspection: ${dev.device_name || "Unknown"} (${dev.device_id})`;

    // Build identification section
    const brand = dev.brand || 'Unidentified';
    const howId = dev.how_identified || 'No identification evidence available';
    const deviceTypeStr = dev.device_type_str || 'Unknown';
    const deviceTypeIcon = dev.device_type_icon || '📶';
    const macTypeStr = dev.mac_type_label || dev.mac_type || 'Unknown';
    const macTypeColor = dev.mac_type_color || '#6b7280';
    const macType = dev.mac_type || 'unknown';
    const macTypeNote = macType === 'public'
      ? 'OUI prefix is usable for vendor lookup.'
      : 'MAC is randomized — OUI prefix is not reliable for identification.';
    
    document.getElementById("modalBody").innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: var(--radius-sm);">
          <div style="font-size: 0.75rem; color: var(--text-secondary);">MAC ADDRESS</div>
          <div class="mac-code" style="font-size: 0.95rem; margin-top: 0.25rem;">${dev.device_id}</div>
          <div style="margin-top: 0.3rem;">
            <span style="background: ${macTypeColor}20; color: ${macTypeColor}; border: 1px solid ${macTypeColor}40; padding: 0.15rem 0.45rem; border-radius: 4px; font-size: 0.68rem; font-weight: 600;">${escapeHtml(macTypeStr)}</span>
            <span style="font-size: 0.65rem; color: var(--text-muted); margin-left: 0.4rem;">${escapeHtml(macTypeNote)}</span>
          </div>
        </div>
        <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: var(--radius-sm);">
          <div style="font-size: 0.75rem; color: var(--text-secondary);">BRAND / MANUFACTURER</div>
          <div style="font-weight: 700; margin-top: 0.25rem; font-size: 1.05rem;">${escapeHtml(brand)}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.2rem;">${escapeHtml(dev.manufacturer || 'Unknown OUI')}</div>
        </div>
        <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: var(--radius-sm);">
          <div style="font-size: 0.75rem; color: var(--text-secondary);">DEVICE TYPE</div>
          <div style="font-weight: 700; margin-top: 0.25rem;">${deviceTypeIcon} ${escapeHtml(deviceTypeStr)}</div>
        </div>
        <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: var(--radius-sm);">
          <div style="font-size: 0.75rem; color: var(--text-secondary);">SECURITY STATUS</div>
          <div style="margin-top: 0.25rem; display: flex; gap: 0.35rem; align-items: center;">
            <span class="badge badge-${(dev.status || "SAFE").toLowerCase()}">${dev.status}</span>
            ${isTrusted ? '<span class="badge badge-trusted">🛡️ TRUSTED</span>' : ''}
          </div>
        </div>
      </div>

      <div style="background: rgba(56,189,248,0.06); border: 1px solid rgba(56,189,248,0.2); border-radius: var(--radius-sm); padding: 0.65rem 0.9rem; margin-bottom: 1.5rem;">
        <div style="font-size: 0.72rem; color: var(--accent-cyan); font-weight: 700; text-transform: uppercase; margin-bottom: 0.2rem;">How Identified</div>
        <div style="font-size: 0.85rem; color: #e2e8f0;">${escapeHtml(howId)}</div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: var(--radius-sm);">
          <div style="font-size: 0.75rem; color: var(--text-secondary);">RISK SCORE / REPUTATION</div>
          <div style="font-weight: 700; margin-top: 0.25rem;">
            Risk: ${Math.round(dev.risk_score)} | Rep: ${Math.round(dev.reputation)}/100
          </div>
        </div>
      </div>

      <div style="margin-bottom: 1.5rem;">
        <div style="font-size: 0.85rem; font-weight: 700; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
          <span>Explainable Risk Scoring Breakdown</span>
          <span style="font-size: 0.75rem; color: var(--text-secondary);">${Array.isArray(dev.reasons) ? dev.reasons.length : 0} Rule(s) / Factor(s)</span>
        </div>
        <div style="background: rgba(0,0,0,0.2); padding: 0.6rem; border-radius: var(--radius-sm);">
          ${(Array.isArray(dev.reasons) && dev.reasons.length > 0)
            ? dev.reasons.map(r => {
                const contrib = Number(r.contribution) || 0;
                const isPositive = contrib > 0;
                return `
                  <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.45rem 0.6rem; margin-bottom: 0.35rem; background: rgba(0,0,0,0.3); border-radius: var(--radius-sm); border-left: 3px solid ${isPositive ? 'var(--status-attack)' : 'var(--accent-cyan)'};">
                    <span style="font-size: 0.85rem; color: #e2e8f0;">${escapeHtml(r.reason || "")}</span>
                    ${contrib > 0 
                      ? `<span style="font-weight: 700; color: var(--status-attack); font-family: var(--font-mono); font-size: 0.85rem; margin-left: 0.5rem; white-space: nowrap;">+${contrib} pts</span>` 
                      : `<span style="color: var(--text-muted); font-size: 0.75rem; margin-left: 0.5rem; white-space: nowrap;">0 pts</span>`}
                  </div>
                `;
              }).join("")
            : `<div style="font-size: 0.8rem; color: var(--text-muted); padding: 0.25rem;">No risk factors detected.</div>`
          }
        </div>
      </div>

      <div style="margin-bottom: 1.5rem;">
        <div style="font-size: 0.85rem; font-weight: 700; margin-bottom: 0.5rem;">SHA-256 Behavioral Fingerprint</div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; background: rgba(0,0,0,0.5); padding: 0.6rem; border-radius: var(--radius-sm); word-break: break-all; color: var(--accent-cyan);">
          ${dev.fingerprint || "None generated"}
        </div>
      </div>

      <div style="margin-bottom: 1.5rem;">
        <div style="font-size: 0.85rem; font-weight: 700; margin-bottom: 0.5rem;">Recent RSSI Signal History (dBm)</div>
        <div style="display: flex; align-items: flex-end; gap: 4px; height: 70px; background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: var(--radius-sm);">
          ${rssiHistory.length === 0 ? '<span style="color:var(--text-muted); font-size:0.75rem;">No RSSI history</span>' : ''}
          ${rssiHistory.map(r => {
            const h = Math.max(10, Math.min(60, 100 + r.rssi));
            return `<div title="${r.rssi} dBm" style="flex:1; height:${h}px; background:var(--accent-cyan); border-radius: 2px;"></div>`;
          }).join('')}
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 0.75rem; flex-wrap: wrap;">
        ${isTrusted
          ? `<button class="btn btn-untrust" onclick="toggleTrustDevice('${dev.device_id}', false); deviceModal.style.display='none';">Remove from Trusted Whitelist</button>`
          : `<button class="btn btn-trust" onclick="toggleTrustDevice('${dev.device_id}', true); deviceModal.style.display='none';">★ Mark as Trusted (Save to Config)</button>`
        }
        ${dev.blocked || dev.quarantined
          ? `<button class="btn btn-success" onclick="unblockDevice('${dev.device_id}'); deviceModal.style.display='none';">Release from Quarantine</button>`
          : `<button class="btn btn-danger" onclick="quarantineDevice('${dev.device_id}'); deviceModal.style.display='none';">Enforce Quarantine</button>`
        }
      </div>
    `;

    deviceModal.style.display = "flex";
  } catch (err) {
    console.error("Failed to inspect device:", err);
  }
}

// --- Actions: Trust / Untrust / Quarantine / Unblock ---
async function toggleTrustDevice(deviceId, trusted) {
  try {
    const res = await fetch(`${API_BASE}/api/v1/devices/${deviceId}/trust`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trusted: trusted })
    });
    if (res.ok) {
      if (trusted) {
        showToast(`Device ${deviceId} marked as TRUSTED and saved to config file!`, "success");
      } else {
        showToast(`Device ${deviceId} removed from trusted config.`, "warning");
      }
      fetchDevices();
      fetchStats();
      fetchEvents();
    }
  } catch (err) {
    console.error("Trust toggle failed:", err);
  }
}

async function quarantineDevice(deviceId) {
  try {
    const res = await fetch(`${API_BASE}/api/v1/devices/${deviceId}/quarantine`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blocked: true })
    });
    if (res.ok) {
      showToast(`Device ${deviceId} has been quarantined.`, "attack");
      fetchDevices();
      fetchStats();
      fetchLedger();
    }
  } catch (err) {
    console.error("Quarantine failed:", err);
  }
}

async function unblockDevice(deviceId) {
  try {
    const res = await fetch(`${API_BASE}/api/v1/devices/${deviceId}/unblock`, { method: "POST" });
    if (res.ok) {
      showToast(`Device ${deviceId} released from quarantine.`, "success");
      fetchDevices();
      fetchStats();
    }
  } catch (err) {
    console.error("Unblock failed:", err);
  }
}

// --- Blockchain / Audit Ledger ---
async function fetchLedger() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/ledger`);
    if (!res.ok) return;
    const data = await res.json();
    renderLedger(data.blocks || []);
  } catch (err) {
    console.error("Failed to fetch ledger:", err);
  }
}

function renderLedger(blocks) {
  if (!blocks || blocks.length === 0) {
    ledgerBlocksContainer.innerHTML = `<div style="text-align:center; color: var(--text-muted);">No blocks recorded yet.</div>`;
    return;
  }

  ledgerBlocksContainer.innerHTML = blocks.map(b => {
    return `
      <div class="block-card">
        <div class="block-header">
          <div class="block-index">BLOCK #${b.index}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${new Date(b.timestamp * 1000).toLocaleTimeString()}</div>
        </div>
        <div class="hash-row">
          <span class="hash-label">Block Hash:</span>
          <span class="hash-val">${b.hash}</span>
        </div>
        <div class="hash-row">
          <span class="hash-label">Previous Hash:</span>
          <span class="hash-val">${b.previous_hash}</span>
        </div>
        <div class="block-payload">
          <pre>${escapeHtml(JSON.stringify(b.data, null, 2))}</pre>
        </div>
      </div>
    `;
  }).join("");
}

async function verifyLedger(tamper = false) {
  try {
    const res = await fetch(`${API_BASE}/api/v1/ledger/verify?tamper=${tamper}`);
    if (!res.ok) return;
    const data = await res.json();
    const statusBox = document.getElementById("ledgerValidationStatus");
    statusBox.style.display = "block";

    if (data.valid) {
      statusBox.style.background = "rgba(16, 185, 129, 0.15)";
      statusBox.style.border = "1px solid var(--status-safe)";
      statusBox.style.color = "#6ee7b7";
      statusBox.innerHTML = `<strong>✅ CRYPTOGRAPHIC INTEGRITY VERIFIED:</strong> All ${data.total_blocks} blocks are sequentially linked with valid SHA-256 hashes. Zero tampering detected.`;
    } else {
      statusBox.style.background = "rgba(239, 68, 68, 0.15)";
      statusBox.style.border = "1px solid var(--status-attack)";
      statusBox.style.color = "#fca5a5";
      const errList = data.errors.map(e => `<li>Block #${e.block_index}: ${e.error}</li>`).join("");
      statusBox.innerHTML = `<strong>🚨 TAMPERING DETECTED IN CHAIN:</strong><ul style="margin-top: 0.5rem; padding-left: 1.2rem;">${errList}</ul>`;
    }
  } catch (err) {
    console.error("Verification failed:", err);
  }
}

async function triggerTamperTest() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/ledger/tamper-test`, { method: "POST" });
    if (res.ok) {
      showToast("Tamper demo activated! Verifying chain...", "warning");
      verifyLedger(true);
    }
  } catch (err) {
    console.error("Tamper test error:", err);
  }
}

async function resetTamperTest() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/ledger/tamper-reset`, { method: "POST" });
    if (res.ok) {
      showToast("Tamper demo reset. Verifying authentic chain...", "success");
      verifyLedger(false);
    }
  } catch (err) {
    console.error("Reset error:", err);
  }
}

// --- Attack Scenario Injection ---
window.injectScenario = async function(scenarioKey) {
  try {
    showToast(`Injecting scenario: ${scenarioKey}...`, "warning");
    const res = await fetch(`${API_BASE}/api/v1/simulation/inject/${scenarioKey}`, { method: "POST" });
    if (!res.ok) return;
    const data = await res.json();
    
    showToast(`Injected ${data.injected_count} devices for scenario '${scenarioKey}'!`, "attack");
    fetchStats();
    fetchDevices();
    fetchLedger();
    fetchEvents();
  } catch (err) {
    console.error("Failed to inject scenario:", err);
  }
};

// --- Simulation Background Stream ---
async function fetchSimStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/simulation/status`);
    if (!res.ok) return;
    const data = await res.json();
    isSimRunning = data.running;
    updateSimButtonUI(isSimRunning);
  } catch (err) {
    console.error("Failed to fetch sim status:", err);
  }
}

async function toggleSimulationStream() {
  try {
    const endpoint = isSimRunning ? "/api/v1/simulation/stop" : "/api/v1/simulation/start";
    const res = await fetch(`${API_BASE}${endpoint}`, { method: "POST" });
    if (res.ok) {
      isSimRunning = !isSimRunning;
      updateSimButtonUI(isSimRunning);
      showToast(isSimRunning ? "Simulation background stream started" : "Simulation stream stopped", "success");
    }
  } catch (err) {
    console.error("Failed to toggle simulation:", err);
  }
}

function updateSimButtonUI(running) {
  if (running) {
    btnToggleSim.innerHTML = `<span>⏹</span> Stop Sim Stream`;
    btnToggleSim.classList.remove("btn-outline");
    btnToggleSim.classList.add("btn-danger");
    systemStatusText.textContent = "SIMULATION STREAM ACTIVE";
  } else {
    btnToggleSim.innerHTML = `<span>▶</span> Start Sim Stream`;
    btnToggleSim.classList.add("btn-outline");
    btnToggleSim.classList.remove("btn-danger");
    systemStatusText.textContent = "ACTIVE SOC MONITOR";
  }
}

// --- AI & ML Telemetry ---
async function fetchModelMetrics() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/models/metrics`);
    if (!res.ok) return;
    const data = await res.json();
    const container = document.getElementById("modelsSummaryCards");
    if (!container) return;

    container.innerHTML = (data.models || []).map(m => `
      <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-color); padding: 1.25rem; border-radius: var(--radius-md);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <h4 style="color: var(--accent-cyan); font-size: 0.95rem;">${escapeHtml(m.name)}</h4>
          <span class="badge badge-safe">${m.status.toUpperCase()}</span>
        </div>
        <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 0.75rem;">${escapeHtml(m.description)}</div>
        <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Architecture: ${m.type}</div>
      </div>
    `).join("");
  } catch (err) {
    console.error("Failed to fetch model metrics:", err);
  }
}

// --- Security Events Log ---
async function fetchEvents() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/events?limit=50`);
    if (!res.ok) return;
    const data = await res.json();
    renderEvents(data.events || []);
  } catch (err) {
    console.error("Failed to fetch events:", err);
  }
}

function renderEvents(events) {
  if (!events || events.length === 0) {
    eventsTableBody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding: 2rem; color: var(--text-muted);">
          No incidents logged yet.
        </td>
      </tr>
    `;
    return;
  }

  eventsTableBody.innerHTML = events.map(ev => {
    const statusClass = (ev.status || "SAFE").toLowerCase();
    const reasons = Array.isArray(ev.reasons) ? ev.reasons : [];
    const reasonText = reasons.length > 0 
      ? reasons.map(r => typeof r === "object" ? r.reason : r).join("; ")
      : "Standard telemetry match";

    return `
      <tr>
        <td style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono); white-space: nowrap;">
          ${new Date(ev.timestamp * 1000).toLocaleTimeString()}
        </td>
        <td><strong>${escapeHtml(ev.device_name || "Unknown")}</strong></td>
        <td><span class="mac-code">${escapeHtml(ev.device_id)}</span></td>
        <td><span class="badge badge-${statusClass}">${ev.status}</span></td>
        <td style="font-weight:700;">${Math.round(ev.risk_score || 0)}</td>
        <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(reasonText)}</td>
      </tr>
    `;
  }).join("");
}

// --- Toast Notifications ---
function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  const icon = type === "attack" ? "🚨" : type === "warning" ? "⚠️" : "✅";
  toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// --- Utilities ---
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
