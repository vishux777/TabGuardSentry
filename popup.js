// Tab Guard Enhanced Popup JavaScript
console.log('Tab Guard v3.0 - Enhanced UI loaded');

class TabGuardPopup {
  constructor() {
    this.currentView = 'dashboard';
    this.stats = { threatsBlocked: 0, tabsMonitored: 0, activitiesDetected: 0 };
    this.settings = this.getDefaultSettings();
    this.updateInterval = null;
    this.currentFilter = 'all';
    this.init();
  }

  getDefaultSettings() {
    return {
      securityLevel: 'medium',
      enableCryptoMining: true,
      enableClipboard: true,
      enableFormMonitor: true,
      enableNetworkGuard: true,
      enablePermissionMonitor: true,
      enableDownloadMonitor: true,
      enableAdvancedThreats: true,
      trustedDomains: [],
      blockedDomains: []
    };
  }

  async init() {
    this.setupNavigation();
    this.setupEventListeners();
    await this.loadData();
    this.startUpdates();
    this.showView('dashboard');
  }

  setupNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const view = e.currentTarget.dataset.view;
        this.showView(view);
      });
    });
  }

  setupEventListeners() {
    // Dashboard
    document.getElementById('refreshBtn')?.addEventListener('click', () => this.loadData());
    document.getElementById('masterSwitch')?.addEventListener('change', (e) => this.toggleProtection(e.target.checked));
    document.getElementById('viewAllBtn')?.addEventListener('click', () => this.showView('threats'));

    // Protection
    document.getElementById('quickScanBtn')?.addEventListener('click', () => this.quickScan());
    document.getElementById('scanAllBtn')?.addEventListener('click', () => this.scanAllTabs());
    document.getElementById('refreshTabsBtn')?.addEventListener('click', () => this.loadTabs());

    // Threats
    document.getElementById('threatFilter')?.addEventListener('change', (e) => this.filterThreats(e.target.value));
    document.getElementById('exportBtn')?.addEventListener('click', () => this.exportThreats());
    document.getElementById('clearBtn')?.addEventListener('click', () => this.clearThreats());

    // Settings
    document.getElementById('saveBtn')?.addEventListener('click', () => this.saveSettings());
    document.getElementById('addTrustedBtn')?.addEventListener('click', () => this.addTrustedDomain());
    document.getElementById('addBlockedBtn')?.addEventListener('click', () => this.addBlockedDomain());
    
    // Settings toggles
    document.querySelectorAll('#settingsView input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', () => this.updateSettingsPreview());
    });

    // Footer
    document.getElementById('emergencyBtn')?.addEventListener('click', () => this.emergencyStop());
    document.getElementById('exportAllBtn')?.addEventListener('click', () => this.exportAllData());
    document.getElementById('helpBtn')?.addEventListener('click', () => this.showHelp());

    // Enter key handlers
    document.getElementById('trustedInput')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addTrustedDomain();
    });
    document.getElementById('blockedInput')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addBlockedDomain();
    });
  }

  showView(viewName) {
    // Update navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === viewName);
    });

    // Update views
    document.querySelectorAll('.view').forEach(view => {
      view.classList.toggle('active', view.id === `${viewName}View`);
    });

    this.currentView = viewName;
    this.loadViewData(viewName);
  }

  async loadViewData(viewName) {
    try {
      switch(viewName) {
        case 'dashboard':
          await this.loadDashboard();
          break;
        case 'protection':
          await this.loadTabs();
          break;
        case 'threats':
          await this.loadThreats();
          break;
        case 'settings':
          await this.loadSettings();
          break;
      }
    } catch (error) {
      console.error(`Error loading ${viewName} view:`, error);
      this.showError(`Failed to load ${viewName} data`);
    }
  }

  async loadData() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_MONITORING_DATA' });
      if (response?.success) {
        this.stats = response.realTimeStats || this.stats;
        this.settings = response.settings || this.settings;
        this.updateStats();
        this.updateStatus();
      }
    } catch (error) {
      console.error('Error loading data:', error);
      this.showError('Failed to load monitoring data');
    }
  }

  updateStats() {
    this.animateNumber('threatsBlocked', this.stats.threatsBlocked || 0);
    this.animateNumber('tabsMonitored', this.stats.tabsMonitored || 0);
    this.animateNumber('activitiesDetected', this.stats.activitiesDetected || 0);
    
    const securityLevel = this.calculateSecurityLevel();
    const securityElement = document.getElementById('securityLevel');
    if (securityElement) {
      securityElement.textContent = securityLevel;
    }
  }

  updateStatus() {
    const badge = document.getElementById('statusBadge');
    if (!badge) return;

    const threatCount = this.stats.threatsBlocked || 0;
    
    badge.className = 'status-badge';
    const statusText = badge.querySelector('.status-text');
    const statusIcon = badge.querySelector('.status-icon');
    
    if (threatCount === 0) {
      badge.classList.add('protected');
      if (statusText) statusText.textContent = 'Protected';
      if (statusIcon) statusIcon.textContent = '✓';
    } else if (threatCount < 5) {
      badge.classList.add('warning');
      if (statusText) statusText.textContent = 'Threats Found';
      if (statusIcon) statusIcon.textContent = '⚠';
    } else {
      badge.classList.add('danger');
      if (statusText) statusText.textContent = 'High Activity';
      if (statusIcon) statusIcon.textContent = '⚠';
    }
  }

  calculateSecurityLevel() {
    const threatCount = this.stats.threatsBlocked || 0;
    if (threatCount === 0) return 'HIGH';
    if (threatCount < 3) return 'MEDIUM';
    return 'LOW';
  }

  animateNumber(elementId, targetValue) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const currentValue = parseInt(element.textContent) || 0;
    const increment = Math.ceil((targetValue - currentValue) / 10);
    
    if (currentValue !== targetValue) {
      const timer = setInterval(() => {
        const current = parseInt(element.textContent) || 0;
        if (current < targetValue) {
          element.textContent = Math.min(current + increment, targetValue);
        } else {
          element.textContent = targetValue;
          clearInterval(timer);
        }
      }, 50);
    }
  }

  async loadDashboard() {
    await this.loadRecentActivity();
    this.updateThreatLevel();
    this.updateProtectionModules();
  }

  async loadRecentActivity() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_ACTIVITY_LOGS' });
      if (response?.success) {
        const activities = (response.logs || []).slice(-3);
        this.renderRecentActivity(activities);
      }
    } catch (error) {
      console.error('Error loading recent activity:', error);
    }
  }

  renderRecentActivity(activities) {
    const container = document.getElementById('activityList');
    if (!container) return;

    if (activities.length === 0) {
      container.innerHTML = `
        <div class="activity-item safe">
          <div class="activity-icon">✅</div>
          <div class="activity-details">
            <div class="activity-title">System Active</div>
            <div class="activity-time">Just now</div>
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = activities.map(activity => `
      <div class="activity-item ${this.getActivityClass(activity.severity)}">
        <div class="activity-icon">${this.getActivityIcon(activity.type)}</div>
        <div class="activity-details">
          <div class="activity-title">${this.formatActivityType(activity.type)}</div>
          <div class="activity-time">${this.formatTime(activity.timestamp)}</div>
        </div>
      </div>
    `).join('');
  }

  getActivityClass(severity) {
    const classes = { critical: 'danger', high: 'danger', medium: 'warning', low: 'safe' };
    return classes[severity] || 'safe';
  }

  getActivityIcon(type) {
    const icons = {
      'CRYPTO_MINING_DETECTED': '⚡',
      'CLIPBOARD_ACCESS': '📋',
      'AUTO_FORM_SUBMISSION': '📝',
      'PHISHING_ATTEMPT': '🎣',
      'SUSPICIOUS_DOWNLOAD': '⬇️',
      'MALICIOUS_SCRIPT': '🔴',
      'SUSPICIOUS_NETWORK_REQUEST': '🌐',
      'PERMISSION_REQUEST': '🔐',
      'SUSPICIOUS_IFRAME': '🖼️',
      'EXCESSIVE_REDIRECTS': '🔄',
      'POPUP_DETECTED': '🪟'
    };
    return icons[type] || '⚠️';
  }

  formatActivityType(type) {
    const names = {
      'CRYPTO_MINING_DETECTED': 'Crypto Mining Blocked',
      'CLIPBOARD_ACCESS': 'Clipboard Access',
      'AUTO_FORM_SUBMISSION': 'Auto Form Submit',
      'PHISHING_ATTEMPT': 'Phishing Blocked',
      'SUSPICIOUS_DOWNLOAD': 'Suspicious Download',
      'MALICIOUS_SCRIPT': 'Malicious Script',
      'SUSPICIOUS_NETWORK_REQUEST': 'Network Threat',
      'PERMISSION_REQUEST': 'Permission Request',
      'SUSPICIOUS_IFRAME': 'Suspicious Iframe',
      'EXCESSIVE_REDIRECTS': 'Multiple Redirects',
      'POPUP_DETECTED': 'Popup Blocked'
    };
    return names[type] || 'Security Event';
  }

  formatTime(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    return `${Math.floor(minutes / 1440)}d ago`;
  }

  updateThreatLevel() {
    const circle = document.getElementById('threatCircle');
    const text = document.getElementById('threatText');
    const riskScore = document.getElementById('riskScore');
    const activeThreats = document.getElementById('activeThreats');
    
    if (!circle || !text) return;

    const threatCount = this.stats.threatsBlocked || 0;
    let level = 'LOW';
    let score = 15;
    let color = '#10b981';
    let percentage = 20;

    if (threatCount > 10) {
      level = 'CRITICAL';
      score = 85;
      color = '#dc2626';
      percentage = 85;
    } else if (threatCount > 5) {
      level = 'HIGH';
      score = 65;
      color = '#f59e0b';
      percentage = 65;
    } else if (threatCount > 0) {
      level = 'MEDIUM';
      score = 35;
      color = '#3b82f6';
      percentage = 35;
    }

    text.textContent = level;
    text.style.color = color;
    if (riskScore) riskScore.textContent = score;
    if (activeThreats) activeThreats.textContent = threatCount;

    // Update circle
    const degrees = (percentage / 100) * 360;
    circle.style.background = `conic-gradient(${color} 0deg ${degrees}deg, #e2e8f0 ${degrees}deg 360deg)`;
  }

  updateProtectionModules() {
    const modules = document.querySelectorAll('.module-indicator');
    modules.forEach(module => {
      module.classList.add('active');
    });
  }

  async loadTabs() {
    const container = document.getElementById('tabsContainer');
    if (!container) return;

    container.innerHTML = '<div class="loading">Loading tabs...</div>';

    try {
      const [tabs, response] = await Promise.all([
        chrome.tabs.query({}),
        chrome.runtime.sendMessage({ action: 'GET_MONITORING_DATA' })
      ]);

      const tabData = response?.tabData || {};
      this.renderTabs(tabs, tabData);
    } catch (error) {
      console.error('Error loading tabs:', error);
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠️</div><div class="empty-title">Failed to load tabs</div></div>';
    }
  }

  renderTabs(tabs, tabData) {
    const container = document.getElementById('tabsContainer');
    if (!container) return;

    if (tabs.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">📱</div><div class="empty-title">No tabs found</div></div>';
      return;
    }

    container.innerHTML = tabs.slice(0, 10).map(tab => {
      const data = tabData[tab.id] || { riskScore: 0, suspiciousActivities: [], threatLevel: 'safe' };
      const activityCount = data.suspiciousActivities?.length || 0;
      
      return `
        <div class="tab-item ${data.threatLevel}">
          <div class="tab-title">${this.escapeHtml(tab.title || 'Untitled')}</div>
          <div class="tab-url">${this.escapeHtml(this.truncateUrl(tab.url || ''))}</div>
          <div class="tab-meta">
            <span>Risk: ${data.riskScore}</span>
            <span>Activities: ${activityCount}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  async loadThreats() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_THREAT_REPORTS' });
      if (response?.success) {
        const threats = response.reports || [];
        this.renderThreatSummary(threats);
        this.renderThreats(threats);
      }
    } catch (error) {
      console.error('Error loading threats:', error);
      this.showError('Failed to load threat reports');
    }
  }

  renderThreatSummary(threats) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    threats.forEach(threat => {
      const severity = this.getThreatSeverity(threat.data?.riskScore || 0);
      counts[severity]++;
    });

    const criticalElement = document.getElementById('criticalCount');
    const highElement = document.getElementById('highCount');
    const mediumElement = document.getElementById('mediumCount');
    const lowElement = document.getElementById('lowCount');

    if (criticalElement) criticalElement.textContent = counts.critical;
    if (highElement) highElement.textContent = counts.high;
    if (mediumElement) mediumElement.textContent = counts.medium;
    if (lowElement) lowElement.textContent = counts.low;
  }

  getThreatSeverity(riskScore) {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 30) return 'medium';
    return 'low';
  }

  renderThreats(threats) {
    const container = document.getElementById('threatsList');
    if (!container) return;

    let filteredThreats = threats;
    if (this.currentFilter !== 'all') {
      filteredThreats = threats.filter(threat => {
        const severity = this.getThreatSeverity(threat.data?.riskScore || 0);
        return severity === this.currentFilter;
      });
    }

    if (filteredThreats.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🛡️</div>
          <div class="empty-title">No Threats Detected</div>
          <div class="empty-subtitle">Your browsing is secure</div>
        </div>
      `;
      return;
    }

    container.innerHTML = filteredThreats.slice(-20).reverse().map(threat => {
      const severity = this.getThreatSeverity(threat.data?.riskScore || 0);
      return `
        <div class="threat-item">
          <div class="threat-header">
            <div class="threat-type">${this.formatActivityType(threat.type)}</div>
            <div class="threat-severity ${severity}">${severity.toUpperCase()}</div>
          </div>
          <div class="threat-details">${this.escapeHtml(threat.data?.reason || 'No details available')}</div>
          <div class="threat-meta">
            <span>${this.formatTime(threat.timestamp)}</span>
            <span>Risk: ${threat.data?.riskScore || 0}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  async loadSettings() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_MONITORING_DATA' });
      if (response?.success && response.settings) {
        this.settings = response.settings;
        this.updateSettingsUI();
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  updateSettingsUI() {
    // Update security level
    const securityRadios = document.querySelectorAll('input[name="securityLevel"]');
    securityRadios.forEach(radio => {
      radio.checked = radio.value === this.settings.securityLevel;
    });

    // Update protection toggles
    const toggles = [
      'enableCryptoMining',
      'enableClipboard',
      'enableFormMonitor',
      'enableNetworkGuard'
    ];

    toggles.forEach(toggleName => {
      const toggle = document.getElementById(toggleName);
      if (toggle) {
        toggle.checked = this.settings[toggleName];
      }
    });

    // Update domain lists
    this.updateDomainLists();
  }

  updateDomainLists() {
    this.renderDomainList('trustedList', this.settings.trustedDomains, 'trusted');
    this.renderDomainList('blockedList', this.settings.blockedDomains, 'blocked');
  }

  renderDomainList(containerId, domains, type) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (domains.length === 0) {
      container.innerHTML = `<div class="empty-state" style="padding: 20px;"><div class="empty-title">No ${type} domains</div></div>`;
      return;
    }

    container.innerHTML = domains.map(domain => `
      <div class="domain-item">
        <span class="domain-name">${this.escapeHtml(domain)}</span>
        <button class="domain-remove" onclick="tabGuardPopup.removeDomain('${type}', '${domain}')">×</button>
      </div>
    `).join('');
  }

  async quickScan() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        await chrome.runtime.sendMessage({ action: 'SCAN_TAB', tabId: tab.id });
        this.showSuccess('Quick scan completed');
        await this.loadTabs();
      }
    } catch (error) {
      console.error('Error performing quick scan:', error);
      this.showError('Quick scan failed');
    }
  }

  async scanAllTabs() {
    try {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        if (tab.id) {
          await chrome.runtime.sendMessage({ action: 'SCAN_TAB', tabId: tab.id });
        }
      }
      this.showSuccess(`Scanned ${tabs.length} tabs`);
      await this.loadTabs();
    } catch (error) {
      console.error('Error scanning all tabs:', error);
      this.showError('Scan all tabs failed');
    }
  }

  filterThreats(severity) {
    this.currentFilter = severity;
    this.loadThreats();
  }

  async exportThreats() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'EXPORT_DATA' });
      if (response?.success) {
        const data = {
          threats: response.data.reports || [],
          exportDate: new Date().toISOString(),
          version: '3.0.0'
        };
        this.downloadJSON(data, 'tab_guard_threats.json');
        this.showSuccess('Threats exported successfully');
      }
    } catch (error) {
      console.error('Error exporting threats:', error);
      this.showError('Failed to export threats');
    }
  }

  async exportAllData() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'EXPORT_DATA' });
      if (response?.success) {
        this.downloadJSON(response.data, 'tab_guard_complete_data.json');
        this.showSuccess('Data exported successfully');
      }
    } catch (error) {
      console.error('Error exporting data:', error);
      this.showError('Failed to export data');
    }
  }

  downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async clearThreats() {
    if (confirm('Are you sure you want to clear all threat reports? This action cannot be undone.')) {
      try {
        await chrome.runtime.sendMessage({ action: 'CLEAR_THREATS' });
        this.showSuccess('Threat reports cleared');
        await this.loadThreats();
        await this.loadDashboard();
      } catch (error) {
        console.error('Error clearing threats:', error);
        this.showError('Failed to clear threats');
      }
    }
  }

  async saveSettings() {
    try {
      // Get security level
      const securityLevel = document.querySelector('input[name="securityLevel"]:checked')?.value || 'medium';
      
      // Get protection toggles
      const newSettings = {
        ...this.settings,
        securityLevel: securityLevel,
        enableCryptoMining: document.getElementById('enableCryptoMining')?.checked || false,
        enableClipboard: document.getElementById('enableClipboard')?.checked || false,
        enableFormMonitor: document.getElementById('enableFormMonitor')?.checked || false,
        enableNetworkGuard: document.getElementById('enableNetworkGuard')?.checked || false
      };

      await chrome.runtime.sendMessage({ action: 'UPDATE_SETTINGS', settings: newSettings });
      this.settings = newSettings;
      this.showSuccess('Settings saved successfully');
    } catch (error) {
      console.error('Error saving settings:', error);
      this.showError('Failed to save settings');
    }
  }

  async addTrustedDomain() {
    const input = document.getElementById('trustedInput');
    if (!input) return;

    const domain = input.value.trim();
    if (!domain) return;

    if (this.isValidDomain(domain) && !this.settings.trustedDomains.includes(domain)) {
      this.settings.trustedDomains.push(domain);
      input.value = '';
      this.updateDomainLists();
      await this.saveSettings();
    } else {
      this.showError('Invalid domain or domain already exists');
    }
  }

  async addBlockedDomain() {
    const input = document.getElementById('blockedInput');
    if (!input) return;

    const domain = input.value.trim();
    if (!domain) return;

    if (this.isValidDomain(domain) && !this.settings.blockedDomains.includes(domain)) {
      this.settings.blockedDomains.push(domain);
      input.value = '';
      this.updateDomainLists();
      await this.saveSettings();
    } else {
      this.showError('Invalid domain or domain already exists');
    }
  }

  async removeDomain(type, domain) {
    const listName = type === 'trusted' ? 'trustedDomains' : 'blockedDomains';
    const index = this.settings[listName].indexOf(domain);
    
    if (index > -1) {
      this.settings[listName].splice(index, 1);
      this.updateDomainLists();
      await this.saveSettings();
    }
  }

  isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
    return domainRegex.test(domain);
  }

  async toggleProtection(enabled) {
    // Toggle all protection modules
    const modules = [
      'enableCryptoMining',
      'enableClipboard', 
      'enableFormMonitor',
      'enableNetworkGuard'
    ];

    modules.forEach(module => {
      this.settings[module] = enabled;
      const toggle = document.getElementById(module);
      if (toggle) toggle.checked = enabled;
    });

    await this.saveSettings();
    this.showSuccess(enabled ? 'Protection enabled' : 'Protection disabled');
  }

  async emergencyStop() {
    if (confirm('Emergency Stop will disable all protection modules. Continue?')) {
      try {
        await chrome.runtime.sendMessage({ action: 'EMERGENCY_STOP' });
        this.showSuccess('Emergency stop activated - all protection disabled');
        await this.loadSettings();
      } catch (error) {
        console.error('Error activating emergency stop:', error);
        this.showError('Failed to activate emergency stop');
      }
    }
  }

  showHelp() {
    const helpWindow = window.open('', '_blank', 'width=600,height=400');
    helpWindow.document.write(`
      <html>
        <head><title>Tab Guard Help</title></head>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
          <h1>Tab Guard Help</h1>
          <h2>Features</h2>
          <ul>
            <li><strong>Crypto Mining Detection:</strong> Blocks cryptocurrency mining scripts</li>
            <li><strong>Clipboard Protection:</strong> Monitors unauthorized clipboard access</li>
            <li><strong>Form Monitoring:</strong> Detects suspicious form submissions</li>
            <li><strong>Network Guard:</strong> Analyzes network requests for threats</li>
          </ul>
          <h2>Security Levels</h2>
          <ul>
            <li><strong>Basic:</strong> Essential protection only</li>
            <li><strong>Balanced:</strong> Recommended for most users</li>
            <li><strong>Maximum:</strong> Highest security, may affect performance</li>
          </ul>
          <p>For more information, visit our documentation.</p>
        </body>
      </html>
    `);
  }

  updateSettingsPreview() {
    // Update preview of current settings
    console.log('Settings preview updated');
  }

  startUpdates() {
    // Update data every 30 seconds
    this.updateInterval = setInterval(() => {
      if (this.currentView === 'dashboard') {
        this.loadData();
      }
    }, 30000);
  }

  stopUpdates() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  showSuccess(message) {
    this.showNotification(message, 'success');
  }

  showError(message) {
    this.showNotification(message, 'error');
  }

  showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 16px;
      border-radius: 6px;
      color: white;
      font-weight: 600;
      z-index: 1000;
      background: ${type === 'success' ? '#10b981' : '#ef4444'};
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.parentNode.removeChild(notification);
        }
      }, 300);
    }, 3000);
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  truncateUrl(url) {
    if (url.length <= 50) return url;
    return url.substring(0, 47) + '...';
  }
}

// Initialize Tab Guard Popup
const tabGuardPopup = new TabGuardPopup();

// Cleanup on window unload
window.addEventListener('beforeunload', () => {
  tabGuardPopup.stopUpdates();
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
`;
document.head.appendChild(style);
