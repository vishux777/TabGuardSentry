// Tab Guard Enhanced Popup JavaScript
console.log('Tab Guard v3.0 - Enhanced UI loaded');

class TabGuardPopup {
  constructor() {
    this.currentView = 'dashboard';
    this.stats = { threatsBlocked: 0, tabsMonitored: 0, activitiesDetected: 0 };
    this.settings = this.getDefaultSettings();
    this.updateInterval = null;
    this.init();
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
  }

  async loadData() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_MONITORING_DATA' });
      if (response?.success) {
        this.stats = response.realTimeStats || this.stats;
        this.updateStats();
        this.updateStatus();
      }
    } catch (error) {
      console.error('Error loading data:', error);
    }
  }

  updateStats() {
    this.animateNumber('threatsBlocked', this.stats.threatsBlocked || 0);
    this.animateNumber('tabsMonitored', this.stats.tabsMonitored || 0);
    this.animateNumber('activitiesDetected', this.stats.activitiesDetected || 0);
    
    const securityLevel = this.calculateSecurityLevel();
    document.getElementById('securityLevel').textContent = securityLevel;
  }

  updateStatus() {
    const badge = document.getElementById('statusBadge');
    const threatCount = this.stats.threatsBlocked || 0;
    
    badge.className = 'status-badge';
    if (threatCount === 0) {
      badge.classList.add('protected');
      badge.querySelector('.status-text').textContent = 'Protected';
    } else if (threatCount < 5) {
      badge.classList.add('warning');
      badge.querySelector('.status-text').textContent = 'Threats Found';
    } else {
      badge.classList.add('danger');
      badge.querySelector('.status-text').textContent = 'High Activity';
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
      'MALICIOUS_SCRIPT': '🔴'
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
      'MALICIOUS_SCRIPT': 'Malicious Script'
    };
    return names[type] || 'Security Event';
  }

  formatTime(timestamp) {
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
    riskScore.textContent = score;
    activeThreats.textContent = threatCount;

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
    }
  }

  renderThreatSummary(threats) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    threats.forEach(threat => {
      const severity = this.getThreatSeverity(threat.data?.riskScore || 0);
      counts[severity]++;
    });

    document.getElementById('criticalCount').textContent = counts.critical;
    document.getElementById('highCount').textContent = counts.high;
    document.getElementById('mediumCount').textContent = counts.medium;
    document.getElementById('lowCount').textContent = counts.low;
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

    if (threats.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🛡️</div>
          <div class="empty-title">No Threats Detected</div>
          <div class="empty-subtitle">Your browsing is secure</div>
        </div>
      `;
      return;
    }

    container.innerHTML = threats.slice(0, 10).map(threat => `
      <div class="activity-item ${this.getActivityClass(this.getThreatSeverity(threat.data?.riskScore || 0))}">
        <div class="activity-icon">${this.getActivityIcon(threat.type)}</div>
        <div class="activity-details">
          <div class="activity-title">${this.formatActivityType(threat.type)}</div>
          <div class="activity-time">${this.formatTime(threat.timestamp)}</div>
        </div>
      </div>
    `).join('');
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['tabGuardSettings']);
      this.settings = { ...this.getDefaultSettings(), ...result.tabGuardSettings };
      this.updateSettingsUI();
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  updateSettingsUI() {
    // Update checkboxes
    Object.keys(this.settings).forEach(key => {
      const element = document.getElementById(key);
      if (element && element.type === 'checkbox') {
        element.checked = this.settings[key];
      }
    });

    // Update radio buttons
    if (this.settings.securityLevel) {
      const radio = document.querySelector(`input[name="securityLevel"][value="${this.settings.securityLevel}"]`);
      if (radio) radio.checked = true;
    }

    // Update domain lists
    this.renderDomainList('trustedList', this.settings.trustedDomains || []);
    this.renderDomainList('blockedList', this.settings.blockedDomains || []);
  }

  renderDomainList(containerId, domains) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = domains.map(domain => `
      <div class="domain-tag">
        ${this.escapeHtml(domain)}
        <button class="domain-remove" onclick="tabGuardPopup.removeDomain('${domain}', '${containerId}')">×</button>
      </div>
    `).join('');
  }

  async saveSettings() {
    try {
      // Collect form data
      const formData = new FormData();
      
      // Checkboxes
      ['cryptoMining', 'clipboardProtection', 'formMonitoring', 'phishingProtection', 'networkMonitoring', 'notifications'].forEach(key => {
        const element = document.getElementById(key);
        if (element) {
          this.settings[key] = element.checked;
        }
      });

      // Security level
      const securityLevel = document.querySelector('input[name="securityLevel"]:checked');
      if (securityLevel) {
        this.settings.securityLevel = securityLevel.value;
      }

      await chrome.storage.local.set({ tabGuardSettings: this.settings });
      this.showNotification('Settings saved successfully', 'success');
    } catch (error) {
      console.error('Error saving settings:', error);
      this.showNotification('Failed to save settings', 'error');
    }
  }

  async addTrustedDomain() {
    const input = document.getElementById('trustedInput');
    const domain = input.value.trim();
    
    if (domain && this.isValidDomain(domain)) {
      if (!this.settings.trustedDomains) this.settings.trustedDomains = [];
      if (!this.settings.trustedDomains.includes(domain)) {
        this.settings.trustedDomains.push(domain);
        this.renderDomainList('trustedList', this.settings.trustedDomains);
        input.value = '';
      }
    }
  }

  async addBlockedDomain() {
    const input = document.getElementById('blockedInput');
    const domain = input.value.trim();
    
    if (domain && this.isValidDomain(domain)) {
      if (!this.settings.blockedDomains) this.settings.blockedDomains = [];
      if (!this.settings.blockedDomains.includes(domain)) {
        this.settings.blockedDomains.push(domain);
        this.renderDomainList('blockedList', this.settings.blockedDomains);
        input.value = '';
      }
    }
  }

  removeDomain(domain, listType) {
    const key = listType === 'trustedList' ? 'trustedDomains' : 'blockedDomains';
    this.settings[key] = this.settings[key].filter(d => d !== domain);
    this.renderDomainList(listType, this.settings[key]);
  }

  async quickScan() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        await chrome.runtime.sendMessage({ action: 'DEEP_SCAN', tabId: tab.id });
        this.showNotification('Quick scan completed', 'success');
      }
    } catch (error) {
      console.error('Quick scan failed:', error);
      this.showNotification('Quick scan failed', 'error');
    }
  }

  async scanAllTabs() {
    try {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        await chrome.runtime.sendMessage({ action: 'DEEP_SCAN', tabId: tab.id });
      }
      this.showNotification(`Scanned ${tabs.length} tabs`, 'success');
    } catch (error) {
      console.error('Scan all failed:', error);
      this.showNotification('Scan all failed', 'error');
    }
  }

  async toggleProtection(enabled) {
    try {
      this.settings.enabled = enabled;
      await chrome.storage.local.set({ tabGuardSettings: this.settings });
      this.updateProtectionStatus(enabled);
    } catch (error) {
      console.error('Toggle protection failed:', error);
    }
  }

  updateProtectionStatus(enabled) {
    const modules = document.querySelectorAll('.module-indicator');
    modules.forEach(module => {
      module.classList.toggle('active', enabled);
    });
  }

  async exportThreats() {
    try {
      await chrome.runtime.sendMessage({ action: 'EXPORT_DATA' });
      this.showNotification('Threats exported successfully', 'success');
    } catch (error) {
      console.error('Export failed:', error);
      this.showNotification('Export failed', 'error');
    }
  }

  async clearThreats() {
    if (confirm('Are you sure you want to clear all threat reports?')) {
      try {
        await chrome.storage.local.set({ threatReports: [] });
        this.renderThreats([]);
        this.renderThreatSummary([]);
        this.showNotification('Threat reports cleared', 'success');
      } catch (error) {
        console.error('Clear threats failed:', error);
        this.showNotification('Clear threats failed', 'error');
      }
    }
  }

  filterThreats(filter) {
    // Implementation for filtering threats by severity
    console.log('Filtering threats by:', filter);
  }

  async exportAllData() {
    try {
      await chrome.runtime.sendMessage({ action: 'EXPORT_DATA' });
      this.showNotification('All data exported successfully', 'success');
    } catch (error) {
      console.error('Export all data failed:', error);
      this.showNotification('Export failed', 'error');
    }
  }

  emergencyStop() {
    if (confirm('This will disable all protection modules. Continue?')) {
      document.getElementById('masterSwitch').checked = false;
      this.toggleProtection(false);
      this.showNotification('Emergency stop activated', 'warning');
    }
  }

  showHelp() {
    const helpContent = `
Tab Guard Security Monitor Help:

Dashboard: View real-time security statistics and recent activity
Protection: Monitor current tabs and run security scans
Threats: Review detected threats and export reports
Settings: Configure security modules and manage domains

For support, contact the extension developer.
    `;
    alert(helpContent.trim());
  }

  updateSettingsPreview() {
    // Live preview of settings changes
    console.log('Settings preview updated');
  }

  startUpdates() {
    this.updateInterval = setInterval(() => {
      if (this.currentView === 'dashboard') {
        this.loadData();
      }
    }, 10000); // Update every 10 seconds
  }

  stopUpdates() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  getDefaultSettings() {
    return {
      cryptoMining: true,
      clipboardProtection: true,
      formMonitoring: true,
      phishingProtection: true,
      networkMonitoring: true,
      notifications: true,
      securityLevel: 'medium',
      trustedDomains: [],
      blockedDomains: [],
      enabled: true
    };
  }

  showNotification(message, type = 'info') {
    // Simple notification system
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
      font-size: 12px;
      font-weight: 600;
      z-index: 10000;
      background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#3b82f6'};
    `;
    
    document.body.appendChild(notification);
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 3000);
  }

  // Utility functions
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  truncateUrl(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  }

  isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    return domainRegex.test(domain);
  }
}

// Initialize popup when DOM is loaded
let tabGuardPopup;
document.addEventListener('DOMContentLoaded', () => {
  tabGuardPopup = new TabGuardPopup();
});

// Cleanup when popup is closed
window.addEventListener('beforeunload', () => {
  if (tabGuardPopup) {
    tabGuardPopup.stopUpdates();
  }
});