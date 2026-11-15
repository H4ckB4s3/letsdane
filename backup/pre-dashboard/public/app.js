async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    document.getElementById('proxy-status').textContent = data.proxy.status === 'active' ? 'Active' : 'Stopped';
    document.getElementById('proxy-address').textContent = data.proxy.address;
    document.getElementById('ca-status').textContent = data.ca.ready ? 'Ready' : 'Not ready';

    if (data.ca.ready) {
      const info = document.getElementById('ca-info');
      info.innerHTML = `
        <dt>Subject</dt><dd>${data.ca.subject}</dd>
        <dt>Issuer</dt><dd>${data.ca.issuer}</dd>
        <dt>Valid from</dt><dd>${new Date(data.ca.notBefore).toLocaleDateString()}</dd>
        <dt>Valid until</dt><dd>${new Date(data.ca.notAfter).toLocaleDateString()}</dd>
        <dt>SHA-256 fingerprint</dt><dd>${data.ca.fingerprint}</dd>
        <dt>Serial</dt><dd>${data.ca.serial}</dd>
      `;
    }
  } catch (err) {
    console.error('Failed to load status', err);
  }
}

loadStatus();
setInterval(loadStatus, 10000);
