
// Simulate Real-Time Threat Updates
const threatLog = document.querySelector('.threat-log');

function addThreat(type, source, action) {
    const threatItem = document.createElement('div');
    threatItem.classList.add('threat-item', 'resolved');
    threatItem.innerHTML = `
        <div class="threat-icon">🛡️</div>
        <div class="threat-details">
            <p><strong>${new Date().toLocaleTimeString()}</strong> - ${type} from ${source} ${action}.</p>
        </div>
    `;
    threatLog.prepend(threatItem);

    // Update threat count
    const threatCount = document.querySelector('.threat-count');
    threatCount.textContent = parseInt(threatCount.textContent) + 1;
}


// Threat Monitoring Functionality
document.querySelectorAll('.resolve-btn').forEach(button => {
    button.addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        row.querySelector('td:nth-child(4)').innerHTML = '<span class="status-resolved">Resolved</span>';
        alert('Threat marked as resolved.');
    });
});

document.querySelectorAll('.block-btn').forEach(button => {
    button.addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        const ip = row.querySelector('td:nth-child(3)').textContent;
        row.querySelector('td:nth-child(4)').innerHTML = '<span class="status-blocked">Blocked</span>';
        alert(`IP ${ip} has been blocked.`);
    });
});

