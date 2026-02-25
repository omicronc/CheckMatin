/*
    CheckMatin
    Copyright (C) 2026  Christophe Chatelain

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Use 'browser' namespace for Firefox, fall back to 'chrome' if needed (though behavior differs)
const browserAPI = (typeof browser !== 'undefined') ? browser : chrome;
const storage = browserAPI.storage.local;

// State
let sites = [];
let manualTasks = [];
let manualResults = [];
let editingId = null;
let currentReportNote = ""; // Store the note for the current session

// DOM Elements
const siteListEl = document.getElementById('site-list');
const modal = document.getElementById('site-modal');
const addBtn = document.getElementById('add-site-btn');
const saveBtn = document.getElementById('save-site-btn');
const cancelBtn = document.getElementById('cancel-btn');
const clearBtn = document.getElementById('clear-results-btn');
const runAllBtn = document.getElementById('run-all-btn');
const emailReportBtn = document.getElementById('email-report');
const gmailReportBtn = document.getElementById('gmail-report');

// Inputs
const urlInput = document.getElementById('site-url');
const nameInput = document.getElementById('site-name');
const checkStatus = document.getElementById('check-status');
const checkScreenshot = document.getElementById('check-screenshot');
const checkContent = document.getElementById('check-content');
const contentOptions = document.getElementById('content-options');
const contentSelector = document.getElementById('content-selector');
const contentText = document.getElementById('content-text');

// Date Inputs
const checkDate = document.getElementById('check-date');
const dateOptions = document.getElementById('date-options');
const dateSelector = document.getElementById('date-selector');
const dateMaxAge = document.getElementById('date-max-age');

// Auth Inputs
const checkAuth = document.getElementById('check-auth');
const authOptions = document.getElementById('auth-options');
const authUser = document.getElementById('auth-user');
const authPass = document.getElementById('auth-pass');
const authUserSel = document.getElementById('auth-user-sel');
const authPassSel = document.getElementById('auth-pass-sel');
const authSubmitSel = document.getElementById('auth-submit-sel');
const authBasic = document.getElementById('auth-basic');
const checkManual = document.getElementById('check-manual');
const downloadReportBtn = document.getElementById('download-report');
const exportBtn = document.getElementById('export-btn');
const importBtn = document.getElementById('import-btn');
const importFile = document.getElementById('import-file');
const sharedJsonUrlInput = document.getElementById('shared-json-url');
const connectSharedJsonBtn = document.getElementById('connect-shared-json-btn');
const sharedJsonStatusEl = document.getElementById('shared-json-status');

const contentGroup = document.getElementById('content-group');
const dateGroup = document.getElementById('date-group');
const manualGroup = document.getElementById('manual-group');
const authGroup = document.getElementById('auth-group');
const contentSummary = document.getElementById('content-summary');
const dateSummary = document.getElementById('date-summary');
const manualSummary = document.getElementById('manual-summary');
const authSummary = document.getElementById('auth-summary');

// Export Modal Elements
const exportModal = document.getElementById('export-modal');
const exportFullBtn = document.getElementById('export-full-btn');
const exportSafeBtn = document.getElementById('export-safe-btn');
const exportClose = document.getElementById('export-close');

// Master Password Elements
const mpModal = document.getElementById('mp-modal');
const mpInput = document.getElementById('mp-input');
const mpError = document.getElementById('mp-error');
const mpCancel = document.getElementById('mp-cancel');
const mpConfirm = document.getElementById('mp-confirm');
const mpClose = document.getElementById('mp-close');

// Note Modal Elements
const noteModal = document.getElementById('note-modal');
const reportNoteInput = document.getElementById('report-note-input');
const saveNoteBtn = document.getElementById('save-note-btn');
const skipNoteBtn = document.getElementById('skip-note-btn');
const manualChecksListEl = document.getElementById('manual-checks-list');

// Manual Config Modal Elements
const configManualBtn = document.getElementById('config-manual-btn');
const manualConfigModal = document.getElementById('manual-config-modal');
const manualConfigClose = document.getElementById('manual-config-close');
const newManualTaskInput = document.getElementById('new-manual-task');
const addManualTaskBtn = document.getElementById('add-manual-task-btn');
const manualTasksListEl = document.getElementById('manual-tasks-list');
const saveManualConfigBtn = document.getElementById('save-manual-config-btn');

// --- CRYPTO UTILS ---

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function bufferToBase64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function encryptData(text, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, enc.encode(text)
    );
    
    return {
        cipher: bufferToBase64(encrypted),
        salt: bufferToBase64(salt),
        iv: bufferToBase64(iv)
    };
}

async function decryptData(encryptedObj, password) {
    try {
        const salt = base64ToBuffer(encryptedObj.salt);
        const iv = base64ToBuffer(encryptedObj.iv);
        const cipher = base64ToBuffer(encryptedObj.cipher);
        const key = await deriveKey(password, salt);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, key, cipher
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        throw new Error("Déchiffrement échoué");
    }
}

// --- MASTER PASSWORD MANAGER ---

const MasterPasswordManager = {
    // Prompt user for password
    requestPassword: function(mode) {
        return new Promise((resolve, reject) => {
            mpModal.classList.remove('hidden'); 
            // Remove inline display style if any, to let CSS class take over (which is flex)
            mpModal.style.display = ''; 
            
            const title = document.getElementById('mp-title');
            const desc = document.getElementById('mp-desc');
            
            if (mode === 'encrypt') {
                title.textContent = "Définir/Confirmer Mot de Passe Maître";
                desc.textContent = "Ce mot de passe chiffrera vos identifiants. Ne l'oubliez pas !";
            } else {
                title.textContent = "Déverrouillage Requis";
                desc.textContent = "Entrez votre mot de passe maître pour déchiffrer les identifiants.";
            }

            mpInput.value = '';
            mpError.style.display = 'none';
            mpInput.focus();

            const cleanup = () => {
                mpConfirm.removeEventListener('click', onConfirm);
                mpCancel.removeEventListener('click', onCancel);
                mpClose.removeEventListener('click', onCancel);
                mpModal.classList.add('hidden');
                mpModal.style.display = '';
            };

            const onConfirm = async () => {
                const pass = mpInput.value;
                if (!pass) {
                    mpError.textContent = "Mot de passe requis";
                    mpError.style.display = 'block';
                    return;
                }
                
                // If checking, we can verify against stored verifier immediately if we want,
                // or let the caller try to decrypt.
                // Let's resolve with the password.
                cleanup();
                resolve(pass);
            };

            const onCancel = () => {
                cleanup();
                reject(new Error("Annulé par l'utilisateur"));
            };

            mpConfirm.addEventListener('click', onConfirm);
            mpCancel.addEventListener('click', onCancel);
            mpClose.addEventListener('click', onCancel);
            
            // Allow Enter key
            mpInput.onkeydown = (e) => {
                if(e.key === 'Enter') onConfirm();
                if(e.key === 'Escape') onCancel();
            };
        });
    },

    verifyOrSet: async function(password) {
        // Check if a verifier exists
        const data = await storage.get('mpVerifier');
        if (data.mpVerifier) {
            // Try to decrypt it
            try {
                const check = await decryptData(data.mpVerifier, password);
                if (check === 'CHECKMATIN_OK') return true;
            } catch(e) {
                return false;
            }
        } else {
            // Create it
            const verifier = await encryptData('CHECKMATIN_OK', password);
            await storage.set({ mpVerifier: verifier });
            return true;
        }
        return false;
    }
};


// Init
document.addEventListener('DOMContentLoaded', () => {
    console.log("CheckMatin: DOMContentLoaded");
    
    // Display Version
    const manifest = browserAPI.runtime.getManifest();
    const versionEl = document.getElementById('app-version');
    if (versionEl) {
        versionEl.textContent = `v${manifest.version}`;
    }

    loadSites();
    
    if (siteListEl) {
        console.log("CheckMatin: Adding event listener to siteListEl");
        siteListEl.addEventListener('click', (e) => {
            // Use closest to handle clicks on child elements
            const editBtn = e.target.closest('.btn-edit');
            const deleteBtn = e.target.closest('.btn-delete');
            const runBtn = e.target.closest('.btn-run');

            if (runBtn) {
                const id = runBtn.getAttribute('data-id');
                console.log("CheckMatin: Run clicked for", id);
                runSingleCheck(id);
            } else if (editBtn) {
                const id = editBtn.getAttribute('data-id');
                console.log("CheckMatin: Edit clicked for", id);
                editSite(id);
            } else if (deleteBtn) {
                const id = deleteBtn.getAttribute('data-id');
                console.log("CheckMatin: Delete clicked for", id);
                deleteSite(id);
            }
        });
    } else {
        console.error("CheckMatin: siteListEl not found!");
    }
});

// Event Listeners
addBtn.addEventListener('click', () => openModal());
cancelBtn.addEventListener('click', closeModal);
saveBtn.addEventListener('click', saveSite);
checkContent.addEventListener('change', toggleContentOptions);
contentSelector.addEventListener('input', toggleContentOptions);
contentText.addEventListener('input', toggleContentOptions);
checkDate.addEventListener('change', toggleDateOptions);
dateSelector.addEventListener('input', toggleDateOptions);
dateMaxAge.addEventListener('input', toggleDateOptions);
checkAuth.addEventListener('change', toggleAuthOptions);
authUser.addEventListener('input', toggleAuthOptions);
authBasic.addEventListener('change', toggleAuthOptions);
checkManual.addEventListener('change', () => {
    manualGroup.classList.toggle('collapsed', !checkManual.checked);
    manualSummary.textContent = checkManual.checked ? 'Activé' : 'Désactivé';
});
runAllBtn.addEventListener('click', runChecks);
emailReportBtn.addEventListener('click', () => generateReport('mailto'));
downloadReportBtn.addEventListener('click', () => generateReport('download'));
clearBtn.addEventListener('click', clearResults);
if (connectSharedJsonBtn) {
    connectSharedJsonBtn.addEventListener('click', connectSharedJson);
}

exportBtn.addEventListener('click', () => {
    exportModal.classList.remove('hidden');
});
exportClose.addEventListener('click', () => {
    exportModal.classList.add('hidden');
});
exportFullBtn.addEventListener('click', () => {
    exportConfig('full');
    exportModal.classList.add('hidden');
});
exportSafeBtn.addEventListener('click', () => {
    exportConfig('safe');
    exportModal.classList.add('hidden');
});

importBtn.addEventListener('click', () => importFile.click());
importFile.addEventListener('change', importConfig);

// Note Modal Listeners
saveNoteBtn.addEventListener('click', () => {
    currentReportNote = reportNoteInput.value;
    
    // Capture Manual Results
    manualResults = [];
    const checkboxes = manualChecksListEl.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => {
        manualResults.push({
            task: cb.dataset.task,
            checked: cb.checked
        });
    });

    noteModal.classList.add('hidden');
    // Maybe scroll to top or highlight actions
    window.scrollTo({ top: 0, behavior: 'smooth' });
    alert("Note et vérifications enregistrées ! Vous pouvez maintenant générer le rapport.");
});

skipNoteBtn.addEventListener('click', () => {
    currentReportNote = "";
    noteModal.classList.add('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
 });
 
 // --- MANUAL CONFIG HANDLERS ---
 
 function renderManualConfigList() {
     manualTasksListEl.innerHTML = '';
     manualTasks.forEach((task, index) => {
         const li = document.createElement('li');
         li.style.padding = '8px';
         li.style.borderBottom = '1px solid #eee';
         li.style.display = 'flex';
         li.style.justifyContent = 'space-between';
         li.style.alignItems = 'center';
         
         const span = document.createElement('span');
         span.textContent = task;
         
         const delBtn = document.createElement('button');
         delBtn.textContent = '❌';
         delBtn.style.background = 'none';
         delBtn.style.border = 'none';
         delBtn.style.cursor = 'pointer';
         delBtn.onclick = () => {
             manualTasks.splice(index, 1);
             renderManualConfigList();
         };
         
         li.appendChild(span);
         li.appendChild(delBtn);
         manualTasksListEl.appendChild(li);
     });
 }
 
 configManualBtn.addEventListener('click', () => {
     renderManualConfigList();
     manualConfigModal.classList.remove('hidden');
 });
 
 manualConfigClose.addEventListener('click', () => {
     manualConfigModal.classList.add('hidden');
 });
 
 addManualTaskBtn.addEventListener('click', () => {
     const task = newManualTaskInput.value.trim();
     if (task) {
         manualTasks.push(task);
         newManualTaskInput.value = '';
         renderManualConfigList();
     }
 });
 
 saveManualConfigBtn.addEventListener('click', async () => {
     await storage.set({ manualTasks });
     manualConfigModal.classList.add('hidden');
     alert('Configuration sauvegardée !');
 });
 
  
 // Functions

async function exportConfig(mode = 'safe') {
    try {
        // Fetch sites, verifier and manual tasks
        const keysToFetch = ['sites', 'manualTasks'];
        if (mode === 'full') {
            keysToFetch.push('mpVerifier');
        }
        
        const data = await storage.get(keysToFetch);
        
        // Clean sites
        if (data.sites) {
            data.sites = data.sites.map(s => {
                const sCopy = {...s};
                
                // Remove history
                sCopy.lastCheck = null; 
                
                // If safe mode, remove sensitive auth data
                if (mode === 'safe' && sCopy.checks) {
                    sCopy.checks.authPass = null;
                    sCopy.checks.authPassEncrypted = null;
                }
                
                return sCopy;
            });
        }
        
        const json = JSON.stringify(data, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        const date = new Date().toISOString().slice(0, 10);
        const suffix = mode === 'full' ? 'FULL' : 'SAFE';
        a.download = `checkmatin-config-${suffix}-${date}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
    } catch (e) {
        console.error("Export failed:", e);
        alert("Erreur lors de l'exportation : " + e.message);
    }
}

async function importConfig(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (!confirm("⚠️ ATTENTION : L'importation va REMPLACER tous vos sites actuels.\n\nVoulez-vous continuer ?")) {
        importFile.value = ''; // Reset input
        return;
    }
    
    const reader = new FileReader();
    reader.onload = async (event) => {
        try {
            const data = JSON.parse(event.target.result);
            
            // Basic validation
            if (!data.sites || !Array.isArray(data.sites)) {
                throw new Error("Format de fichier invalide (pas de liste de sites trouvée)");
            }
            
            // Save sites
            await storage.set({ sites: data.sites });

            // Save manual tasks (default to empty if missing in import to overwrite existing ones)
            await storage.set({ manualTasks: data.manualTasks || [] });
            
            // Save verifier if present (to keep passwords working)
            if (data.mpVerifier) {
                await storage.set({ mpVerifier: data.mpVerifier });
            } else {
                // If importing file without verifier, but we have encrypted passwords...
                // They will be unusable unless user sets same password again manually?
                // Or maybe the user already has a verifier that works?
                // Let's just warn if we detect encrypted passwords but no verifier in import
                const hasEncrypted = data.sites.some(s => s.checks.authPassEncrypted);
                if (hasEncrypted) {
                    alert("Note : Cette configuration contient des mots de passe chiffrés mais pas de vérificateur de mot de passe maître.\n\nSi votre mot de passe maître actuel est différent de celui d'origine, les connexions échoueront.");
                }
            }
            
            // Reload UI
            loadSites();
            alert("✅ Importation réussie !");
            
        } catch (err) {
            console.error("Import failed:", err);
            alert("Erreur lors de l'importation : " + err.message);
        } finally {
            importFile.value = ''; // Reset input
        }
    };
    reader.readAsText(file);
}

async function loadSites() {
    try {
        const data = await storage.get(['sites', 'manualTasks']);
        sites = data.sites || [];
        manualTasks = data.manualTasks || [];
        renderList();
        await initSharedJson();
    } catch (e) {
        console.error("Error loading data:", e);
    }
}

function stableStringify(value) {
    if (Array.isArray(value)) {
        return '[' + value.map(v => stableStringify(v)).join(',') + ']';
    } else if (value && typeof value === 'object') {
        const keys = Object.keys(value).sort();
        return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
    } else {
        return JSON.stringify(value);
    }
}

function cleanSharedUrl(raw) {
    if (!raw) return '';
    let url = raw.trim();
    if ((url.startsWith('"') && url.endsWith('"')) || (url.startsWith("'") && url.endsWith("'"))) {
        url = url.slice(1, -1).trim();
    }
    return url;
}

async function computeHash(text) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function setSharedStatus(message, mode) {
    if (!sharedJsonStatusEl) return;
    sharedJsonStatusEl.textContent = message;
    sharedJsonStatusEl.style.display = 'inline-block';
    sharedJsonStatusEl.classList.remove('alert-ok');
    sharedJsonStatusEl.classList.remove('alert-error');
    sharedJsonStatusEl.classList.remove('alert-blink');
    if (mode === 'ok') {
        sharedJsonStatusEl.classList.add('alert-ok');
    } else {
        sharedJsonStatusEl.classList.add('alert-error');
        sharedJsonStatusEl.classList.add('alert-blink');
    }
}

function hideSharedStatus() {
    if (!sharedJsonStatusEl) return;
    sharedJsonStatusEl.style.display = 'none';
    sharedJsonStatusEl.classList.remove('alert-blink');
}

async function fetchRemoteJsonViaBackground(url) {
    try {
        const res = await browserAPI.runtime.sendMessage({ type: 'fetchRemoteJson', url });
        if (res && res.ok && res.text) {
            return res.text;
        }
        throw new Error(res && res.error ? res.error : 'Fetch error');
    } catch (e) {
        throw e;
    }
}

async function fetchRemoteJson(url) {
    try {
        const resp = await fetch(url, { credentials: 'omit' });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const text = await resp.text();
        return text;
    } catch (e) {
        return await fetchRemoteJsonViaBackground(url);
    }
}

async function mergeRemoteData(remote) {
    let changed = false;
    const previousSites = Array.isArray(sites) ? JSON.parse(JSON.stringify(sites)) : [];
    let sitesPayload = null;
    if (Array.isArray(remote)) {
        sitesPayload = remote;
    } else if (remote && Array.isArray(remote.sites)) {
        sitesPayload = remote.sites;
    }

    if (sitesPayload) {
        if (!sites || sites.length === 0) {
            sites = sitesPayload.map(rs => {
                const nextChecks = { ...(rs.checks || {}) };
                nextChecks.authPassEncrypted = null;
                nextChecks.authPass = null;
                return {
                    id: rs.id || Date.now().toString(),
                    url: rs.url,
                    name: rs.name || '',
                    checks: nextChecks,
                    lastCheck: null
                };
            });
            changed = true;
        } else {
            sitesPayload.forEach(rs => {
                let idx = -1;
                if (rs.id) {
                    idx = sites.findIndex(s => s.id === rs.id);
                }
                if (idx === -1) {
                    idx = sites.findIndex(s => s.url === rs.url);
                }
                if (idx !== -1) {
                    const old = sites[idx];
                    const nextChecks = { ...(old.checks || {}), ...(rs.checks || {}) };
                    const next = {
                        id: old.id,
                        url: rs.url || old.url,
                        name: rs.name !== undefined ? rs.name : old.name,
                        checks: nextChecks,
                        lastCheck: old.lastCheck || null
                    };
                    const before = stableStringify(old);
                    const after = stableStringify(next);
                    if (before !== after) {
                        sites[idx] = next;
                        changed = true;
                    }
                } else {
                    const nextChecks = { ...(rs.checks || {}) };
                    nextChecks.authPassEncrypted = null;
                    nextChecks.authPass = null;
                    const newSite = {
                        id: rs.id || Date.now().toString(),
                        url: rs.url,
                        name: rs.name || '',
                        checks: nextChecks,
                        lastCheck: null
                    };
                    sites.push(newSite);
                    changed = true;
                }
            });
        }

        const authById = new Map();
        const authByUrl = new Map();
        previousSites.forEach(s => {
            const c = s.checks || {};
            if (c && (c.authPass || c.authPassEncrypted)) {
                const authData = {
                    auth: c.auth,
                    authUser: c.authUser,
                    authPass: c.authPass,
                    authPassEncrypted: c.authPassEncrypted,
                    authUserSel: c.authUserSel,
                    authPassSel: c.authPassSel,
                    authSubmitSel: c.authSubmitSel,
                    authBasic: c.authBasic
                };
                if (s.id) authById.set(s.id, authData);
                if (s.url) authByUrl.set(s.url, authData);
            }
        });

        if (authById.size > 0 || authByUrl.size > 0) {
            sites = sites.map(s => {
                const c = { ...(s.checks || {}) };
                let authData = null;
                if (s.id && authById.has(s.id)) {
                    authData = authById.get(s.id);
                } else if (s.url && authByUrl.has(s.url)) {
                    authData = authByUrl.get(s.url);
                }
                if (authData) {
                    c.auth = authData.auth !== undefined ? authData.auth : true;
                    c.authUser = authData.authUser;
                    c.authPass = authData.authPass;
                    c.authPassEncrypted = authData.authPassEncrypted;
                    c.authUserSel = authData.authUserSel;
                    c.authPassSel = authData.authPassSel;
                    c.authSubmitSel = authData.authSubmitSel;
                    c.authBasic = authData.authBasic;
                    changed = true;
                }
                return { ...s, checks: c };
            });
        }
    }
    if (remote && Array.isArray(remote.manualTasks)) {
        manualTasks = remote.manualTasks.slice();
        changed = true;
    }
    if (changed) {
        await storage.set({ sites, manualTasks });
        renderList();
    }
    return changed;
}

async function checkSharedJson() {
    const data = await storage.get(['sharedJsonUrl', 'sharedJsonLastHash']);
    const stored = data.sharedJsonUrl || '';
    const currentInput = sharedJsonUrlInput ? sharedJsonUrlInput.value : '';
    const raw = stored || currentInput;
    const url = cleanSharedUrl(raw);
    if (sharedJsonUrlInput && url) sharedJsonUrlInput.value = url;
    if (!url) {
        hideSharedStatus();
        return;
    }
    try {
        const text = await fetchRemoteJson(url);
        let parsed = null;
        try {
            parsed = JSON.parse(text);
        } catch (e) {
            setSharedStatus('JSON invalide', 'error');
            return;
        }
        const normalized = stableStringify(parsed);
        const hash = await computeHash(normalized);
        const last = data.sharedJsonLastHash || '';

        const didMerge = await mergeRemoteData(parsed);

        if (!last) {
            await storage.set({ sharedJsonLastHash: hash });
            setSharedStatus('JSON OK', 'ok');
        } else if (last !== hash) {
            await storage.set({ sharedJsonLastHash: hash });
            setSharedStatus(didMerge ? 'JSON modifié' : 'JSON vérifié', 'error');
        } else {
            setSharedStatus(didMerge ? 'JSON resynchronisé' : 'JSON OK', 'ok');
        }
    } catch (e) {
        setSharedStatus('JSON inaccessible', 'error');
    }
}

async function connectSharedJson() {
    if (!sharedJsonUrlInput) return;
    const url = cleanSharedUrl(sharedJsonUrlInput.value);
    if (!url) {
        await storage.set({ sharedJsonUrl: '' });
        hideSharedStatus();
        return;
    }
    await storage.set({ sharedJsonUrl: url });
    await checkSharedJson();
}

async function initSharedJson() {
    const data = await storage.get(['sharedJsonUrl']);
    if (sharedJsonUrlInput && data.sharedJsonUrl) {
        sharedJsonUrlInput.value = data.sharedJsonUrl;
    }
    await checkSharedJson();
}

function createElement(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
}

function createBadge(label, active) {
    const span = createElement('span', 'card-badge', active ? `✅ ${label}` : `⬜ ${label}`);
    return span;
}

function buildSiteCard(site) {
    const card = createElement('div', 'site-card');

    const h3 = createElement('h3', 'card-title', site.name || site.url);
    card.appendChild(h3);

    const urlDiv = createElement('div', 'card-url', site.url);
    card.appendChild(urlDiv);

    const badgesDiv = createElement('div', 'card-badges');
    badgesDiv.appendChild(createBadge('Status', site.checks.status));
    badgesDiv.appendChild(createBadge('Capture', site.checks.screenshot));
    badgesDiv.appendChild(createBadge('Contenu', site.checks.content));
    badgesDiv.appendChild(createBadge('Date', site.checks.date));
    badgesDiv.appendChild(createBadge('Manuel', site.checks.manual));
    badgesDiv.appendChild(createBadge('Auth', site.checks.auth));
    card.appendChild(badgesDiv);

    if (site.lastCheck) {
        const resultDiv = createElement('div', 'card-result');

        const dateDiv = createElement('div', 'card-result-date');

        const statusBadge = createElement(
            'span',
            site.lastCheck.success ? 'status-badge status-success' : 'status-badge status-fail',
            site.lastCheck.success ? 'OK' : 'ERREUR'
        );
        const dateSmall = createElement('small', '', ' ' + new Date(site.lastCheck.timestamp).toLocaleString());
        dateDiv.appendChild(statusBadge);
        dateDiv.appendChild(dateSmall);
        resultDiv.appendChild(dateDiv);

        if (site.lastCheck.error) {
            const errorDiv = createElement('div', 'card-result-error', site.lastCheck.error);
            resultDiv.appendChild(errorDiv);
        }

        if (site.lastCheck.screenshot) {
            const link = createElement('a');
            link.href = site.lastCheck.screenshot;
            link.target = '_blank';

            const img = createElement('img', 'screenshot-preview');
            img.src = site.lastCheck.screenshot;
            link.appendChild(img);
            resultDiv.appendChild(link);
        }

        card.appendChild(resultDiv);
    } else {
        const noResultDiv = createElement('div', 'card-no-result', 'Aucune vérification effectuée');
        card.appendChild(noResultDiv);
    }

    const btnDiv = createElement('div', 'card-actions');

    const runBtn = createElement('button', 'primary btn-run', '▶️ Vérifier');
    runBtn.dataset.id = site.id;
    runBtn.classList.add('btn-flex');

    const editBtn = createElement('button', 'secondary btn-edit', 'Éditer');
    editBtn.dataset.id = site.id;

    const deleteBtn = createElement('button', 'secondary btn-delete btn-delete-danger', 'Supprimer');
    deleteBtn.dataset.id = site.id;

    btnDiv.appendChild(runBtn);
    btnDiv.appendChild(editBtn);
    btnDiv.appendChild(deleteBtn);
    card.appendChild(btnDiv);

    return card;
}

function renderList() {
    siteListEl.innerHTML = '';
    const frag = document.createDocumentFragment();
    sites.forEach(site => {
        frag.appendChild(buildSiteCard(site));
    });
    siteListEl.appendChild(frag);
}

function openModal(site = null) {
    if (site) {
        editingId = site.id;
        urlInput.value = site.url;
        nameInput.value = site.name;
        checkStatus.checked = site.checks.status;
        checkScreenshot.checked = site.checks.screenshot;
        checkContent.checked = site.checks.content;
        contentSelector.value = site.checks.contentSelector || '';
        contentText.value = site.checks.contentText || '';
        
        // Date
        checkDate.checked = site.checks.date || false;
        dateSelector.value = site.checks.dateSelector || '';
        dateMaxAge.value = site.checks.dateMaxAge || '';

        // Manual
        checkManual.checked = site.checks.manual || false;

        // Auth
        checkAuth.checked = site.checks.auth || false;
        authUser.value = site.checks.authUser || '';
        // If password is encrypted, we don't show it (or show a placeholder)
        if (site.checks.authPassEncrypted) {
            authPass.value = '';
            authPass.placeholder = "Mot de passe chiffré (laissez vide pour garder)";
        } else {
            authPass.value = site.checks.authPass || '';
            authPass.placeholder = "********";
        }
        
        authUserSel.value = site.checks.authUserSel || '';
        authPassSel.value = site.checks.authPassSel || '';
        authSubmitSel.value = site.checks.authSubmitSel || '';
        authBasic.checked = !!site.checks.authBasic;
    } else {
        editingId = null;
        urlInput.value = '';
        nameInput.value = '';
        checkStatus.checked = true;
        checkScreenshot.checked = false;
        checkContent.checked = false;
        contentSelector.value = '';
        contentText.value = '';

        // Date
        checkDate.checked = false;
        dateSelector.value = '';
        dateMaxAge.value = '';

        // Manual
        checkManual.checked = false;

        // Auth
        checkAuth.checked = false;
        authUser.value = '';
        authPass.value = '';
        authUserSel.value = '';
        authPassSel.value = '';
        authSubmitSel.value = '';
        authBasic.checked = false;
    }
    toggleContentOptions();
    toggleDateOptions();
    toggleAuthOptions();
    manualGroup.classList.toggle('collapsed', !checkManual.checked);
    manualSummary.textContent = checkManual.checked ? 'Activé' : 'Désactivé';
    modal.classList.remove('hidden');
}

function closeModal() {
    modal.classList.add('hidden');
    editingId = null;
}

function toggleContentOptions() {
    if (checkContent.checked) {
        contentOptions.classList.remove('hidden');
        contentGroup.classList.remove('collapsed');
        const sel = contentSelector.value ? contentSelector.value : '(aucun sélecteur)';
        const txt = contentText.value ? `, texte: "${contentText.value}"` : '';
        contentSummary.textContent = `Activé (${sel}${txt})`;
    } else {
        contentOptions.classList.add('hidden');
        contentGroup.classList.add('collapsed');
        contentSummary.textContent = 'Désactivé';
    }
}

function toggleDateOptions() {
    if (checkDate.checked) {
        dateOptions.classList.remove('hidden');
        dateGroup.classList.remove('collapsed');
        const sel = dateSelector.value ? dateSelector.value : '(aucun sélecteur)';
        const age = dateMaxAge.value ? `${dateMaxAge.value} min` : 'n.c.';
        dateSummary.textContent = `Activé (${sel}, max: ${age})`;
    } else {
        dateOptions.classList.add('hidden');
        dateGroup.classList.add('collapsed');
        dateSummary.textContent = 'Désactivé';
    }
}

function toggleAuthOptions() {
    if (checkAuth.checked) {
        authOptions.classList.remove('hidden');
        authGroup.classList.remove('collapsed');
        const mode = authBasic && authBasic.checked ? 'HTTP Basic' : 'Formulaire';
        const u = authUser.value ? authUser.value : 'utilisateur n.c.';
        authSummary.textContent = `Activé (${mode}, ${u})`;
    } else {
        authOptions.classList.add('hidden');
        authGroup.classList.add('collapsed');
        authSummary.textContent = 'Désactivé';
    }
}

async function saveSite() {
    let url = urlInput.value;
    if (!url) return alert('L\'URL est requise');
    
    if (!url.startsWith('http')) {
        url = 'https://' + url;
    }

    // Auth Password Handling
    let finalAuthPass = null;
    let finalAuthPassEncrypted = null;
    
    // If auth is enabled
    if (checkAuth.checked) {
        // If user entered a new password
        if (authPass.value) {
            try {
                // Request Master Password
                const mp = await MasterPasswordManager.requestPassword('encrypt');
                
                // Verify if it matches existing verifier (if any)
                const isValid = await MasterPasswordManager.verifyOrSet(mp);
                if (!isValid) {
                    alert("Mot de passe maître incorrect (ne correspond pas à celui utilisé précédemment).");
                    return; // Stop save
                }
                
                // Encrypt
                finalAuthPassEncrypted = await encryptData(authPass.value, mp);
                finalAuthPass = null; // Ensure plain text is null
                
            } catch (err) {
                console.warn("Save cancelled or failed:", err);
                return; // Stop save if cancelled
            }
        } else {
            // No new password entered. 
            // If editing, keep existing encrypted/plain value
            if (editingId) {
                const oldSite = sites.find(s => s.id === editingId);
                if (oldSite) {
                    finalAuthPassEncrypted = oldSite.checks.authPassEncrypted;
                    finalAuthPass = oldSite.checks.authPass; // Should be null if encrypted
                }
            }
        }
    }

    const newSite = {
        id: editingId || Date.now().toString(),
        url,
        name: nameInput.value,
        checks: {
            status: checkStatus.checked,
            screenshot: checkScreenshot.checked,
            content: checkContent.checked,
            contentSelector: contentSelector.value,
            contentText: contentText.value,
            // Date
            date: checkDate.checked,
            dateSelector: dateSelector.value,
            dateMaxAge: dateMaxAge.value,
            // Manual
            manual: checkManual.checked,
            // Auth
            auth: checkAuth.checked,
            authUser: authUser.value,
            authPass: finalAuthPass,
            authPassEncrypted: finalAuthPassEncrypted,
            authUserSel: authUserSel.value,
            authPassSel: authPassSel.value,
            authSubmitSel: authSubmitSel.value,
            authBasic: authBasic.checked
        },
        lastCheck: editingId ? (sites.find(s => s.id === editingId)?.lastCheck) : null
    };

    if (editingId) {
        const index = sites.findIndex(s => s.id === editingId);
        sites[index] = newSite;
    } else {
        sites.push(newSite);
    }

    await storage.set({ sites });
    renderList();
    closeModal();
}

function editSite(id) {
    const site = sites.find(s => s.id === id);
    if (site) openModal(site);
}

async function deleteSite(id) {
    if (confirm('Voulez-vous vraiment supprimer ce site ?')) {
        sites = sites.filter(s => s.id !== id);
        await storage.set({ sites });
        renderList();
    }
}

async function clearResults() {
    sites = sites.map(s => ({ ...s, lastCheck: null }));
    await storage.set({ sites });
    renderList();
}

async function generateReport(type = 'mailto') {
    if (!sites || sites.length === 0) {
        alert("Aucun site configuré.");
        return;
    }

    const now = new Date();
    const dateStr = now.toLocaleString();
    const dateShort = now.toLocaleDateString();
    
    // --- 1. Prepare Content ---
    let plainBody = "Rapport de vérification CheckMatin\n";
    plainBody += "Généré le : " + dateStr + "\n\n";
    
    if (currentReportNote) {
        plainBody += "NOTE :\n" + currentReportNote + "\n\n";
        plainBody += "----------------------------------------\n\n";
    }

    if (manualResults && manualResults.length > 0) {
        plainBody += "VÉRIFICATIONS MANUELLES :\n";
        manualResults.forEach(res => {
            plainBody += (res.checked ? "[OK] " : "[--] ") + res.task + "\n";
        });
        plainBody += "----------------------------------------\n\n";
    }

    // Build DOM Report
    const reportRoot = document.createElement('div');
    reportRoot.style.fontFamily = 'sans-serif';
    reportRoot.style.color = '#333';

    const h2 = document.createElement('h2');
    h2.style.color = '#2c3e50';
    h2.textContent = 'Rapport CheckMatin';
    reportRoot.appendChild(h2);

    const pDate = document.createElement('p');
    const strongDate = document.createElement('strong');
    strongDate.textContent = 'Généré le : ';
    pDate.appendChild(strongDate);
    pDate.appendChild(document.createTextNode(dateStr));
    reportRoot.appendChild(pDate);

    if (currentReportNote) {
        const noteDiv = document.createElement('div');
        noteDiv.style.backgroundColor = '#fff3cd';
        noteDiv.style.border = '1px solid #ffeeba';
        noteDiv.style.color = '#856404';
        noteDiv.style.padding = '15px';
        noteDiv.style.margin = '20px 0';
        noteDiv.style.borderRadius = '4px';
        
        const strongNote = document.createElement('strong');
        strongNote.textContent = 'Note : ';
        noteDiv.appendChild(strongNote);
        noteDiv.appendChild(document.createElement('br'));
        
        // Handle newlines in note
        currentReportNote.split('\n').forEach((line, index) => {
             if (index > 0) noteDiv.appendChild(document.createElement('br'));
             noteDiv.appendChild(document.createTextNode(line));
        });
        
        reportRoot.appendChild(noteDiv);
    }

    if (manualResults && manualResults.length > 0) {
        const manualDiv = document.createElement('div');
        manualDiv.style.marginBottom = '20px';
        manualDiv.style.padding = '15px';
        manualDiv.style.backgroundColor = '#e3f2fd'; // Light blue
        manualDiv.style.border = '1px solid #bbdefb';
        manualDiv.style.borderRadius = '4px';

        const h4 = document.createElement('h4');
        h4.textContent = 'Vérifications Manuelles';
        h4.style.marginTop = '0';
        h4.style.marginBottom = '10px';
        h4.style.color = '#0d47a1';
        manualDiv.appendChild(h4);

        const ul = document.createElement('ul');
        ul.style.listStyle = 'none';
        ul.style.padding = '0';
        ul.style.margin = '0';
        
        manualResults.forEach(res => {
            const li = document.createElement('li');
            li.style.padding = '4px 0';
            li.style.display = 'flex';
            li.style.alignItems = 'center';
            
            const icon = document.createElement('span');
            icon.style.marginRight = '8px';
            icon.textContent = res.checked ? '✅' : '❌';
            
            const text = document.createElement('span');
            text.textContent = res.task;
            if (!res.checked) text.style.color = '#c62828'; // Red color for failed/unchecked
            
            li.appendChild(icon);
            li.appendChild(text);
            ul.appendChild(li);
        });
        
        manualDiv.appendChild(ul);
        reportRoot.appendChild(manualDiv);
    }

    let hasResults = false;
    let successCount = 0;
    let failCount = 0;
    
    // We'll append sites to a fragment first
    const sitesFragment = document.createDocumentFragment();
    let sitesPlain = '';

    sites.forEach(site => {
        if (site.lastCheck) {
            hasResults = true;
            const isSuccess = site.lastCheck.success;
            const statusIcon = isSuccess ? "✅" : "❌";
            if (isSuccess) successCount++; else failCount++;

            // Plain Text
            sitesPlain += `=== ${site.name || site.url} ===\n`;
            if (!site.name) {
                sitesPlain += `URL: ${site.url}\n`;
            }
            sitesPlain += `Statut: ${statusIcon} ${isSuccess ? 'SUCCÈS' : 'ERREUR'}\n`;
            
            // HTML DOM
            const siteDiv = document.createElement('div');
            siteDiv.style.marginBottom = '30px';
            siteDiv.style.border = '1px solid #eee';
            siteDiv.style.padding = '15px';
            siteDiv.style.borderRadius = '5px';
            siteDiv.style.backgroundColor = '#f9f9f9';

            const h3 = document.createElement('h3');
            h3.style.marginTop = '0';
            h3.style.color = isSuccess ? '#2e7d32' : '#c62828';
            
            const linkTitle = document.createElement('a');
            linkTitle.href = site.url;
            linkTitle.style.textDecoration = 'none';
            linkTitle.style.color = 'inherit';
            linkTitle.textContent = `${statusIcon} ${site.name || site.url}`;
            h3.appendChild(linkTitle);
            siteDiv.appendChild(h3);
            
            if (!site.name) {
                const pUrl = document.createElement('p');
                pUrl.style.margin = '5px 0';
                const linkUrl = document.createElement('a');
                linkUrl.href = site.url;
                linkUrl.style.color = '#1976d2';
                linkUrl.textContent = site.url;
                pUrl.appendChild(linkUrl);
                siteDiv.appendChild(pUrl);
            }
                
            const ul = document.createElement('ul');
            ul.style.margin = '10px 0';
            ul.style.paddingLeft = '20px';

            // Checks details
            const checks = [];
            if (site.checks.status) checks.push(site.lastCheck.success ? "HTTP: OK" : "HTTP: ERR");
            if (site.checks.content) checks.push(site.lastCheck.checks?.content ? "Contenu: OK" : "Contenu: ERR");
            if (site.checks.date) checks.push(site.lastCheck.checks?.date ? "Date: OK" : "Date: ERR");
            
            if (checks.length > 0) {
                sitesPlain += `Checks: ${checks.join(', ')}\n`;
                checks.forEach(c => {
                    const li = document.createElement('li');
                    li.textContent = c;
                    ul.appendChild(li);
                });
                siteDiv.appendChild(ul);
            }

            if (site.lastCheck.error) {
                sitesPlain += `Erreur: ${site.lastCheck.error}\n`;
                const pErr = document.createElement('p');
                pErr.style.color = 'red';
                pErr.style.fontWeight = 'bold';
                pErr.textContent = `Erreur : ${site.lastCheck.error}`;
                siteDiv.appendChild(pErr);
            }
            
            if (site.lastCheck.logs && site.lastCheck.logs.length > 0) {
                sitesPlain += `Logs:\n- ${site.lastCheck.logs.join('\n- ')}\n`;
                
                const divLogs = document.createElement('div');
                divLogs.style.fontSize = '0.9em';
                divLogs.style.color = '#666';
                divLogs.style.background = '#fff';
                divLogs.style.padding = '10px';
                divLogs.style.border = '1px solid #ddd';
                
                const strongLogs = document.createElement('strong');
                strongLogs.textContent = 'Logs:';
                divLogs.appendChild(strongLogs);
                divLogs.appendChild(document.createElement('br'));
                
                // Safe way to add logs with line breaks
                site.lastCheck.logs.forEach((log, index) => {
                    divLogs.appendChild(document.createTextNode(log));
                    if (index < site.lastCheck.logs.length - 1) {
                         divLogs.appendChild(document.createElement('br'));
                    }
                });
                
                siteDiv.appendChild(divLogs);
            }
            
            // Image
            if (site.lastCheck.screenshot) {
                sitesPlain += `[Capture d'écran disponible dans le rapport HTML]\n`;
                
                const divImg = document.createElement('div');
                divImg.style.marginTop = '15px';
                
                const pImg = document.createElement('p');
                const strongImg = document.createElement('strong');
                strongImg.textContent = "Capture d'écran :";
                pImg.appendChild(strongImg);
                divImg.appendChild(pImg);
                
                const img = document.createElement('img');
        img.src = site.lastCheck.screenshot;
        // Keep original resolution source, but display small
        img.style.maxWidth = '100%'; 
        img.style.width = '400px'; 
        img.style.height = 'auto';
        img.style.border = '1px solid #ccc';
                img.style.boxShadow = '0 2px 5px rgba(0,0,0,0.1)';
                img.alt = `Screenshot ${site.name || site.url}`;
                
                divImg.appendChild(img);
                siteDiv.appendChild(divImg);
            }
            
            sitesPlain += "\n----------------------------------------\n\n";
            sitesFragment.appendChild(siteDiv);
        }
    });

    if (!hasResults) {
        alert("Aucun résultat de vérification disponible. Veuillez lancer les vérifications d'abord.");
        return;
    }
    
    // Summary
    let summaryPlain = `Résumé Sites : ${successCount} OK / ${failCount} ERREUR\n`;
    
    if (typeof manualResults !== 'undefined' && manualResults && manualResults.length > 0) {
        const manualSuccess = manualResults.filter(r => r.checked).length;
        const manualFail = manualResults.filter(r => !r.checked).length;
        summaryPlain += `Résumé Tâches : ${manualSuccess} OK / ${manualFail} ERREUR\n`;
    }
    summaryPlain += "\n";

    plainBody = summaryPlain + sitesPlain;
    
    const pSummary = document.createElement('p');
    const strongSummary = document.createElement('strong');
    strongSummary.textContent = 'Résumé Sites : ';
    pSummary.appendChild(strongSummary);
    
    const spanSummary = document.createElement('span');
    spanSummary.style.color = failCount > 0 ? 'red' : 'green';
    spanSummary.style.fontWeight = 'bold';
    spanSummary.textContent = `${successCount} OK / ${failCount} ERREUR`;
    pSummary.appendChild(spanSummary);
    
    if (typeof manualResults !== 'undefined' && manualResults && manualResults.length > 0) {
        const manualSuccess = manualResults.filter(r => r.checked).length;
        const manualFail = manualResults.filter(r => !r.checked).length;

        pSummary.appendChild(document.createElement('br'));
        
        const strongManual = document.createElement('strong');
        strongManual.textContent = 'Résumé Tâches : ';
        pSummary.appendChild(strongManual);
        
        const spanManual = document.createElement('span');
        spanManual.style.color = manualFail > 0 ? 'red' : 'green';
        spanManual.style.fontWeight = 'bold';
        spanManual.textContent = `${manualSuccess} OK / ${manualFail} ERREUR`;
        pSummary.appendChild(spanManual);
    }

    reportRoot.appendChild(pSummary);
    
    const hr = document.createElement('hr');
    hr.style.border = '0';
    hr.style.borderTop = '1px solid #ccc';
    hr.style.margin = '20px 0';
    reportRoot.appendChild(hr);
    
    reportRoot.appendChild(sitesFragment);
    // reportRoot.appendChild(document.createTextNode('</div>')); // not needed, we are appending nodes

    // --- 2. Copy or Download ---
    
    // Get HTML string from DOM
    const htmlBody = reportRoot.outerHTML;

    if (type === 'download') {
        const fullHtml = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport CheckMatin</title>
</head>
<body style="font-family: sans-serif; padding: 20px;">
    ${htmlBody}
</body>
</html>`;
        
        const blob = new Blob([fullHtml], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `CheckMatin_Rapport_${dateShort.replace(/\//g, '-')}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        return;
    }

    try {
        // --- Copy to Clipboard ---
        
        // 1. Try Clipboard API with HTML (if supported by browser/permissions)
        if (typeof ClipboardItem !== "undefined") {
            try {
                const blobHtml = new Blob([htmlBody], { type: "text/html" });
                const blobText = new Blob([plainBody], { type: "text/plain" });
                const data = [new ClipboardItem({ 
                    "text/html": blobHtml,
                    "text/plain": blobText
                })];
                
                await navigator.clipboard.write(data);
                
                alert("📋 Rapport copié !\n\nSi les images sont invisibles dans votre mail (Gmail...), c'est une sécurité de votre messagerie.\n\n👉 Solution : Utilisez le bouton 'Télécharger Rapport' et envoyez le fichier HTML en pièce jointe.");
                return; // Success
            } catch (clipboardErr) {
                console.warn("ClipboardItem failed, trying fallback...", clipboardErr);
            }
        }
        
        // 2. Fallback method using DOM element (more robust for some contexts but less secure)
        const copyHelper = (domElement, text) => {
            const container = document.createElement('div');
            container.style.position = 'fixed';
            container.style.pointerEvents = 'none';
            container.style.opacity = 0;
            // container.innerHTML = html; // UNSAFE
            container.appendChild(domElement.cloneNode(true)); // SAFE
            document.body.appendChild(container);
            
            window.getSelection().removeAllRanges();
            
            const range = document.createRange();
            range.selectNode(container);
            window.getSelection().addRange(range);
            
            document.execCommand('copy');
            
            document.body.removeChild(container);
        };

        copyHelper(reportRoot, plainBody);
        
        alert("📋 Rapport copié !\n\nSi les images sont invisibles dans votre mail (Gmail...), c'est une sécurité de votre messagerie.\n\n👉 Solution : Utilisez le bouton 'Télécharger Rapport' et envoyez le fichier HTML en pièce jointe.");
    } catch (err) {
        console.error("Clipboard error:", err);
        alert("Erreur lors de la copie : " + err.message);
    }
}

// ---------------- CHECK LOGIC ---------------- //

async function runSingleCheck(id) {
    const site = sites.find(s => s.id === id);
    if (!site) return;

    const btn = document.querySelector(`.btn-run[data-id="${id}"]`);
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ ...';
    }

    try {
        // Decryption logic
        let siteToCheck = site;
        if (site.checks.auth && site.checks.authPassEncrypted) {
             try {
                // If we already have the password in memory (e.g. from previous run checks), we could use it?
                // But we don't store it globally for security.
                // We must ask again or check if verifier allows silent unlock (not implemented securely without caching)
                // So we ask.
                const mp = await MasterPasswordManager.requestPassword('decrypt');
                const pass = await decryptData(site.checks.authPassEncrypted, mp);
                
                siteToCheck = JSON.parse(JSON.stringify(site));
                siteToCheck.checks.authPass = pass;
            } catch (err) {
                // Cancelled or wrong password
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '▶️ Vérifier';
                }
                return;
            }
        }

        const checkWindow = await browserAPI.windows.create({ focused: true, state: "maximized" });
        
        await checkSite(siteToCheck, checkWindow.id);
        
        await browserAPI.windows.remove(checkWindow.id);

        await storage.set({ sites });
        renderList();

    } catch (e) {
        console.error("Single Check Error", e);
        alert("Erreur: " + e.message);
    } finally {
        // If renderList was called, button reference is lost/recreated, so no need to reset old button
        // If renderList was NOT called (error), we might want to reset
        const newBtn = document.querySelector(`.btn-run[data-id="${id}"]`);
        if (newBtn) {
            newBtn.disabled = false;
            newBtn.textContent = '▶️ Vérifier';
        }
    }
}

async function runChecks() {
    runAllBtn.disabled = true;
    runAllBtn.textContent = "Vérification en cours...";
    
    try {
        // --- DECRYPTION STEP ---
        // Identify sites needing decryption
        const sitesToDecrypt = sites.filter(s => s.checks.auth && s.checks.authPassEncrypted);
        let decryptedPasswords = new Map(); // Map<siteId, password>

        if (sitesToDecrypt.length > 0) {
            try {
                const mp = await MasterPasswordManager.requestPassword('decrypt');
                
                // Try decrypt all
                for (const site of sitesToDecrypt) {
                    try {
                        const pass = await decryptData(site.checks.authPassEncrypted, mp);
                        decryptedPasswords.set(site.id, pass);
                    } catch (e) {
                        console.error(`Failed to decrypt for site ${site.name}`, e);
                        throw new Error("Mot de passe maître incorrect (déchiffrement impossible)");
                    }
                }
            } catch (err) {
                alert(err.message);
                // Stop everything if auth failed
                return;
            }
        }

        // Create a new window to run checks
        const checkWindow = await browserAPI.windows.create({ focused: true, state: "maximized" });
        
        for (let i = 0; i < sites.length; i++) {
            const site = sites[i];
            
            // Show status in UI
            const card = siteListEl.children[i];
            if(card) {
                // simple visual feedback
                card.style.opacity = '0.5';
            }

            // Inject decrypted password if needed
            let siteToCheck = site;
            if (decryptedPasswords.has(site.id)) {
                // Clone site object to avoid modifying storage state in memory permanently
                // But we need to pass the clear password to checkSite
                siteToCheck = JSON.parse(JSON.stringify(site));
                siteToCheck.checks.authPass = decryptedPasswords.get(site.id);
            }

            await checkSite(siteToCheck, checkWindow.id);
            
            if(card) card.style.opacity = '1';
            
            // Save progress (update the ORIGINAL site object in the array with results)
            // Note: checkSite updates 'site' object? No, checkSite updates 'sites' array?
            // Wait, checkSite logic needs to be checked.
            // Ah, checkSite finds index in 'sites' and updates it.
            // We need to make sure we don't save the clear password back to storage!
            // The 'siteToCheck' is a copy, so 'checkSite' logic needs adjustment or we pass result back.
            
            // Let's look at checkSite implementation...
            // It does: const index = sites.findIndex(s => s.id === site.id); sites[index].lastCheck = result;
            // So it updates the global 'sites' array.
            // Since we passed a copy 'siteToCheck' to the logic, but the logic uses 'site.id', it's fine.
            // BUT, checkSite USES 'site' passed in argument for execution.
            // So we pass 'siteToCheck' (with clear password) for execution.
            // The result update happens on 'sites' global array.
            // Perfect.
            
            await storage.set({ sites });
            renderList();
        }
        
        await browserAPI.windows.remove(checkWindow.id);
        
        // Open Note Modal & Manual Checks
        reportNoteInput.value = ""; // Reset
        
        // Initialize manualResults with default values (unchecked)
        manualResults = manualTasks.map(t => ({ task: t, checked: false }));

        // Render Manual Checks in Modal
        manualChecksListEl.innerHTML = '';
        if (manualTasks.length === 0) {
            manualChecksListEl.innerHTML = '<p style="color:#666; font-style:italic;">Aucune tâche configurée.</p>';
        } else {
            manualTasks.forEach((task, index) => {
                const div = document.createElement('div');
                div.style.marginBottom = '5px';
                
                const label = document.createElement('label');
                label.style.display = 'flex';
                label.style.alignItems = 'center';
                label.style.cursor = 'pointer';
                
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.style.marginRight = '8px';
                checkbox.dataset.task = task;
                
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(task));
                div.appendChild(label);
                
                manualChecksListEl.appendChild(div);
            });
        }

        noteModal.classList.remove('hidden');

    } catch (e) {
        console.error("Global Check Error", e);
        alert("Erreur lors des vérifications: " + e.message);
    } finally {
        runAllBtn.disabled = false;
        runAllBtn.textContent = "Tout vérifier";
    }
}

async function checkSite(site, windowId) {
    console.log(`Checking ${site.url}...`);
    let result = {
        timestamp: Date.now(),
        success: true,
        logs: [],
        checks: {},
        screenshot: null,
        error: null
    };

    let tab = null;

    try {
        const useBasicAuth = site.checks.auth && site.checks.authBasic && site.checks.authUser && site.checks.authPass;
        let targetUrl = site.url;
        if (useBasicAuth) {
            try {
                const u = new URL(site.url);
                u.username = site.checks.authUser;
                u.password = site.checks.authPass;
                targetUrl = u.toString();
                result.logs.push("Authentification HTTP Basic via URL.");
            } catch (e) {
                console.warn("Failed to build basic auth URL", e);
                result.logs.push("Impossible de construire l'URL d'authentification HTTP Basic.");
            }
        }

        // 1. Create Tab
        tab = await browserAPI.tabs.create({ windowId, url: targetUrl, active: true });
        
        // 2. Wait for load
        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error("Timeout loading page")), 30000);
            
            const listener = (tabId, info) => {
                if (tabId === tab.id && info.status === 'complete') {
                    browserAPI.tabs.onUpdated.removeListener(listener);
                    clearTimeout(timeout);
                    // Give it a little extra time for dynamic content
                    setTimeout(resolve, 2000);
                }
            };
            browserAPI.tabs.onUpdated.addListener(listener);
        });

        // 2.5 Auth (Login) if enabled (HTML form mode only)
        if (site.checks.auth && !(site.checks.authBasic && site.checks.authUser && site.checks.authPass)) {
             console.log("Attempting authentication...");
             result.logs.push("Tentative de connexion...");
             
             // Define selectors with fallbacks
             const userSel = site.checks.authUserSel || 'input[type="text"], input[name="username"], input[name="email"]';
             const passSel = site.checks.authPassSel || 'input[type="password"]';
             const submitSel = site.checks.authSubmitSel || 'button[type="submit"], input[type="submit"]';
             
             try {
                // Inject login script
                const loginResult = await browserAPI.scripting.executeScript({
                    target: { tabId: tab.id },
                    func: async (uSel, pSel, sSel, user, pass) => {
                        const uInput = document.querySelector(uSel);
                        const pInput = document.querySelector(pSel);
                        const sBtn = document.querySelector(sSel);
                        
                        if (!uInput) return { success: false, message: `Champ utilisateur non trouvé (${uSel})` };
                        if (!pInput) return { success: false, message: `Champ mot de passe non trouvé (${pSel})` };
                        if (!sBtn) return { success: false, message: `Bouton de connexion non trouvé (${sSel})` };
                        
                        // Fill inputs
                        uInput.value = user;
                        uInput.dispatchEvent(new Event('input', { bubbles: true }));
                        uInput.dispatchEvent(new Event('change', { bubbles: true }));
                        
                        pInput.value = pass;
                        pInput.dispatchEvent(new Event('input', { bubbles: true }));
                        pInput.dispatchEvent(new Event('change', { bubbles: true }));
                        
                        // Click submit
                        sBtn.click();
                        return { success: true };
                    },
                    args: [userSel, passSel, submitSel, site.checks.authUser, site.checks.authPass]
                });
                
                const res = loginResult[0].result;
                if (!res.success) {
                    throw new Error(res.message);
                }
                
                // Wait for navigation/reload after login
                await new Promise((resolve) => {
                     // Simple delay for now to allow network request and reload
                     // A more robust way would be to listen for onUpdated again
                     setTimeout(resolve, 5000); 
                });
                
                result.logs.push("Commande de connexion envoyée. Attente de 5s...");
                
             } catch (authErr) {
                 console.warn("Auth failed:", authErr);
                 result.logs.push("Échec de l'authentification: " + authErr.message);
                 // We continue, maybe the page is accessible anyway? 
                 // Or we could throw error. Let's just log for now.
             }
        }

        // 2.8 Manual Validation
        if (site.checks.manual) {
            console.log("Waiting for manual validation...");
            
            // Bring window to front
            await browserAPI.windows.update(windowId, { focused: true });
            
            // Define Injection Function (must be self-contained)
            const injectManualUI = () => {
                const HOST_ID = 'checkmatin-manual-host';
                if (document.getElementById(HOST_ID)) return;

                const host = document.createElement('div');
                host.id = HOST_ID;
                host.style.position = 'fixed';
                host.style.top = '0';
                host.style.left = '0';
                host.style.width = '0';
                host.style.height = '0';
                host.style.zIndex = '2147483647'; // Max z-index
                document.body.appendChild(host);

                const shadow = host.attachShadow({ mode: 'open' });

                const container = document.createElement('div');
                container.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background-color: white;
                    padding: 20px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.5);
                    border-radius: 8px;
                    font-family: sans-serif;
                    border: 2px solid #2c3e50;
                    color: #333;
                    font-size: 16px;
                    line-height: 1.5;
                    box-sizing: border-box;
                    width: auto;
                    height: auto;
                    max-width: 300px;
                `;
                
                container.innerHTML = `
                    <h3 style="margin-top:0; margin-bottom: 10px; color:#2c3e50; font-size: 18px; font-weight: bold;">Validation CheckMatin</h3>
                    <p style="margin: 0 0 15px 0;">Veuillez vérifier cette page.</p>
                    <div style="display:flex; gap:10px;">
                        <button id="cm-ok" style="background:#2ecc71; color:white; border:none; padding:10px 20px; cursor:pointer; font-weight:bold; border-radius:4px; font-size: 14px;">✅ VALIDER</button>
                        <button id="cm-fail" style="background:#e74c3c; color:white; border:none; padding:10px 20px; cursor:pointer; font-weight:bold; border-radius:4px; font-size: 14px;">❌ REJETER</button>
                    </div>
                `;
                
                shadow.appendChild(container);

                const btnOk = shadow.getElementById('cm-ok');
                const btnFail = shadow.getElementById('cm-fail');

                const send = (success) => {
                    const api = (typeof browser !== 'undefined') ? browser : chrome;
                    api.runtime.sendMessage({ type: 'MANUAL_VALIDATION', success: success });
                    const el = document.getElementById(HOST_ID);
                    if(el) el.remove();
                };

                btnOk.onclick = () => send(true);
                btnFail.onclick = () => send(false);
            };

            // Initial Injection with Retry
            const tryInjectManualUI = async (retries = 3) => {
                for (let i = 0; i < retries; i++) {
                    try {
                        await browserAPI.scripting.executeScript({
                            target: { tabId: tab.id },
                            func: injectManualUI
                        });
                        return;
                    } catch (e) {
                        console.warn(`Injection attempt ${i+1} failed:`, e);
                        // If it's a "Frame with ID 0" error, it usually means navigation is happening.
                        // We wait a bit and retry.
                        if (i < retries - 1) await new Promise(r => setTimeout(r, 1000));
                    }
                }
                console.error("Manual UI injection failed after retries. Waiting for navigation...");
            };

            await tryInjectManualUI();

            // Listeners
            let onUpdatedListener;
            let onRemovedListener;
            let onMessageListener;

            try {
                const manualResult = await new Promise((resolve, reject) => {
                    
                    // 1. Message Listener (Success/Fail)
                    onMessageListener = (message, sender) => {
                        if (message.type === 'MANUAL_VALIDATION' && sender.tab && sender.tab.id === tab.id) {
                            resolve(message.success);
                        }
                    };
                    browserAPI.runtime.onMessage.addListener(onMessageListener);

                    // 2. Update Listener (Re-inject on navigation)
                    onUpdatedListener = (tabId, info) => {
                        if (tabId === tab.id && info.status === 'complete') {
                            // Re-inject with a small delay to ensure page is ready
                            setTimeout(() => {
                                tryInjectManualUI();
                            }, 500);
                        }
                    };
                    browserAPI.tabs.onUpdated.addListener(onUpdatedListener);

                    // 3. Removed Listener (Tab closed)
                    onRemovedListener = (tabId) => {
                        if (tabId === tab.id) {
                            reject(new Error("Onglet fermé pendant la validation manuelle"));
                        }
                    };
                    browserAPI.tabs.onRemoved.addListener(onRemovedListener);
                });

                if (!manualResult) {
                    result.checks.manual = false;
                    throw new Error("Validation manuelle rejetée par l'utilisateur.");
                } else {
                    result.checks.manual = true;
                    result.logs.push("Validation manuelle: OK");
                }

            } finally {
                // Cleanup listeners
                if (onMessageListener) browserAPI.runtime.onMessage.removeListener(onMessageListener);
                if (onUpdatedListener) browserAPI.tabs.onUpdated.removeListener(onUpdatedListener);
                if (onRemovedListener) browserAPI.tabs.onRemoved.removeListener(onRemovedListener);
            }
        }

        // 3. Status (Fetch check)
        if (site.checks.status) {
            try {
                // Use fetch to check status code
                // Added credentials: 'include' to pass cookies if needed
                const response = await fetch(site.url, { method: 'GET', credentials: 'include' });
                if (!response.ok) {
                    throw new Error(`HTTP Error: ${response.status}`);
                }
            } catch (err) {
                console.warn("Fetch check failed:", err);
                // Do not fail the whole check if the tab loaded successfully.
                // Just log it as a warning.
                result.logs.push("Attention: Le code statut HTTP n'a pas pu être vérifié (" + err.message + "). Mais la page s'est chargée.");
            }
        }

        // 4. Check Content (Scripting)
        if (site.checks.content && site.checks.contentSelector) {
            // Note: browser.scripting.executeScript in Firefox returns an array of results
            const scriptResult = await browserAPI.scripting.executeScript({
                target: { tabId: tab.id },
                func: (selector, text) => {
                    const el = document.querySelector(selector);
                    if (!el) return { found: false, message: `Sélecteur "${selector}" non trouvé` };
                    if (text && !el.textContent.includes(text)) return { found: false, message: `Texte "${text}" non trouvé dans "${selector}"` };
                    return { found: true };
                },
                args: [site.checks.contentSelector, site.checks.contentText]
            });
            
            // scriptResult is an array of objects { frameId, result }
            const res = scriptResult[0].result;
            if (!res.found) {
                throw new Error(res.message);
            }
        }

        // 4.5 Date Check
        if (site.checks.date && site.checks.dateSelector && site.checks.dateMaxAge) {
            console.log("Checking date...");
            const dateResult = await browserAPI.scripting.executeScript({
                target: { tabId: tab.id },
                func: (selector, maxAgeMinutes) => {
                    const el = document.querySelector(selector);
                    if (!el) return { success: false, message: "Élément de date non trouvé" };
                    
                    const text = el.innerText || el.textContent || el.getAttribute('datetime') || el.value;
                    if (!text) return { success: false, message: "Contenu de date vide" };

                    const date = new Date(text);
                    if (isNaN(date.getTime())) {
                        return { success: false, message: `Format de date invalide: "${text}"` };
                    }

                    const now = new Date();
                    const diffMs = now - date;
                    const diffMinutes = diffMs / (1000 * 60);

                    if (diffMinutes < 0) {
                        return { success: true, age: 0, text: text };
                    }

                    if (diffMinutes <= maxAgeMinutes) {
                        return { success: true, age: Math.round(diffMinutes), text: text };
                    } else {
                        return { success: false, age: Math.round(diffMinutes), text: text, message: `Obsolète (${Math.round(diffMinutes)} min > ${maxAgeMinutes} min)` };
                    }
                },
                args: [site.checks.dateSelector, parseInt(site.checks.dateMaxAge)]
            });

            const res = dateResult[0].result;
            if (res.success) {
                result.logs.push(`Date OK : ${res.age} min (Max: ${site.checks.dateMaxAge}) - "${res.text}"`);
            } else {
                throw new Error(`Date Check Failed: ${res.message}`);
            }
        }

        // 5. Screenshot
        if (site.checks.screenshot) {
            // Ensure window is focused (sometimes needed)
            await browserAPI.windows.update(windowId, { focused: true });
            
            // Full Page Screenshot Logic
            // If it fails or takes too long, we want to fail gracefully
            // Let's implement a timeout race
            const screenshotPromise = captureFullPage(tab.id, windowId);
            const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Screenshot timeout")), 15000));
            
            try {
                result.screenshot = await Promise.race([screenshotPromise, timeoutPromise]);
            } catch(e) {
                console.warn("Full page screenshot failed, falling back to visible tab", e);
                 // Fallback to visible tab
                result.screenshot = await browserAPI.tabs.captureVisibleTab(windowId, { format: 'png' });
                result.logs.push("Full page screenshot failed: " + e.message);
            }
        }

    } catch (error) {
        console.error(error);
        result.success = false;
        result.error = error.message;
    } finally {
        if (tab) {
             await browserAPI.tabs.remove(tab.id);
        }
    }

    // Update site
    const index = sites.findIndex(s => s.id === site.id);
    if (index !== -1) {
        sites[index].lastCheck = result;
    }
}

async function captureFullPage(tabId, windowId) {
    // Simplified robust approach:
    // 1. Get dimensions
    const dimensions = (await browserAPI.scripting.executeScript({
        target: { tabId },
        func: () => {
            return {
                width: document.documentElement.scrollWidth,
                height: document.documentElement.scrollHeight,
                windowHeight: window.innerHeight,
                pixelRatio: window.devicePixelRatio
            };
        }
    }))[0].result;

    const { width, height, windowHeight, pixelRatio } = dimensions;

    // 2. Prepare canvas
    const canvas = document.createElement('canvas');
    canvas.width = width * pixelRatio;
    canvas.height = height * pixelRatio;
    const ctx = canvas.getContext('2d');

    let currentY = 0;
    
    // Safety break to prevent infinite loops
    let iterations = 0;
    const maxIterations = 50; 

    while (currentY < height && iterations < maxIterations) {
        iterations++;
        
        // Scroll
        await browserAPI.scripting.executeScript({
            target: { tabId },
            func: (y) => window.scrollTo(0, y),
            args: [currentY]
        });
        
        // Wait for render
        await new Promise(r => setTimeout(r, 800));
        
        // Verify where we are
        const scrollInfo = (await browserAPI.scripting.executeScript({
            target: { tabId },
            func: () => ({ y: window.scrollY, h: window.innerHeight })
        }))[0].result;
        
        // Capture
    // Use jpeg to reduce memory usage during stitching if possible, but captureVisibleTab only returns what it sees
    const dataUrl = await browserAPI.tabs.captureVisibleTab(windowId, { format: 'jpeg', quality: 80 });
    
    await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            const drawY = scrollInfo.y * pixelRatio;
            ctx.drawImage(img, 0, drawY);
            resolve();
        };
        img.onerror = reject;
        img.src = dataUrl;
    });

    // Calculate next step
    // If we are at the bottom, stop
    if (scrollInfo.y + scrollInfo.h >= height - 2) { // tolerance
        break;
    }
    
    currentY += windowHeight;
}

// Return Full Size JPEG
// Quality 0.7 to balance size/quality
return canvas.toDataURL('image/jpeg', 0.7);
}
