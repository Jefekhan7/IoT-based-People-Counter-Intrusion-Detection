// Poll server every second
setInterval(() => {
    fetch('/events').then(res => res.json()).then(data => updateEvents(data));
    fetch('/summary').then(res => res.json()).then(data => updateSummary(data));
}, 1000);

function updateEvents(events) {
    const pre = document.getElementById('decrypted-json');
    // Show latest 10 events
    pre.textContent = JSON.stringify(events.slice(-10).reverse(), null, 2);

    const tbody = document.querySelector('#events-table tbody');
    tbody.innerHTML = '';
    events.slice(-10).reverse().forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${e.timestamp}</td>
            <td>${e.esp_id}</td>
            <td>${e.event}</td>
            <td>${e.people}</td>
            <td style="color:${e.intrusion?'red':'green'}">${e.intrusion}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateSummary(summary){
    document.getElementById('total-entries').textContent = summary.total_entries;
    document.getElementById('total-exits').textContent = summary.total_exits;
    document.getElementById('current-people').textContent = summary.current_people;
    document.getElementById('intrusions').textContent = summary.intrusions;

    const alert = document.getElementById('intrusion-alert');
    if(summary.intrusions > 0){
        alert.classList.remove('hidden');
        setTimeout(()=>alert.classList.add('hidden'), 5000); // auto-hide
    }
}
