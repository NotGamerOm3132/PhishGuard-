const API_BASE = "http://127.0.0.1:5000";

const el = (id) => document.getElementById(id);

// -------------------------------
// VIEW SWITCHING
// -------------------------------
function showView(name) {
  ["dashboard", "history", "scanner", "password"].forEach((v) => {
    const node = document.getElementById("view-" + v);
    node.style.display = v === name ? "" : "none";
  });
}

// -------------------------------
// DASHBOARD
// -------------------------------
async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    const j = await res.json();

    el("stat-total").innerText = j.total ?? 0;
    el("stat-safe").innerText = j.safe ?? 0;
    el("stat-unsafe").innerText = j.unsafe ?? 0;
    el("stat-points").innerText = j.safety_points ?? 0;

    const recent = j.recent_threats || [];
    const ul = el("recent-threats");
    ul.innerHTML = "";

    if (recent.length === 0) {
      ul.innerHTML = '<li class="list-group-item">No recent threats</li>';
    } else {
      recent.forEach((r) => {
        const d = new Date(r.timestamp * 1000);
        const li = document.createElement("li");
        li.className = "list-group-item d-flex justify-content-between align-items-start";
        li.innerHTML = `<div>
                          <strong>${r.url}</strong>
                          <div class="text-muted small">
                            score: ${r.score} — ${d.toLocaleString()}
                          </div>
                        </div>`;
        ul.appendChild(li);
      });
    }
  } catch (e) {
    console.error(e);
  }
}

// -------------------------------
// HISTORY
// -------------------------------
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const j = await res.json();

    const tbody = document.querySelector("#history-table tbody");
    tbody.innerHTML = "";

    j.forEach((row) => {
      const d = new Date(row.timestamp * 1000);
      const tr = document.createElement("tr");

      tr.innerHTML = `<td>${d.toLocaleString()}</td>
                      <td>${row.url}</td>
                      <td>${row.result}</td>
                      <td>${row.score}</td>`;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

// -------------------------------
// SCANNER
// -------------------------------
async function doScan() {
  const url = el("input-url").value.trim();
  if (!url) return alert("Enter a URL to scan");

  el("btn-scan").disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const j = await res.json();

    const analysisDiv = el("analysis");
    const resultDiv = el("analysis-result");
    analysisDiv.style.display = "block";

    resultDiv.innerHTML = `
      <p><strong>URL:</strong> ${j.url}</p>
      <p><strong>Status:</strong> ${j.status}</p>
      <p><strong>Score:</strong> ${j.score ?? "N/A"}</p>
      <p><strong>Domain:</strong> ${j.details?.netloc ?? ""}</p>
      <p><strong>Scheme:</strong> ${j.details?.scheme ?? ""}</p>
      <p><strong>Entropy:</strong> ${j.details?.entropy ?? ""}</p>
      <p><strong>Reasons:</strong></p>
      <ul>${(j.details?.score_breakdown_reasons || []).map(r => `<li>${r}</li>`).join("")}</ul>
    `;

    await loadStats();
    await loadHistory();
  } catch (err) {
    console.error(err);
    alert("Scan failed. Is the backend running?");
  } finally {
    el("btn-scan").disabled = false;
  }
}

// -------------------------------
// PASSWORD CHECKER
// -------------------------------
async function doPasswordCheck() {
  const pwd = el("password-input").value.trim();
  if (!pwd) return alert("Enter a password");

  try {
    const res = await fetch(`${API_BASE}/api/check_password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd }),
    });

    const j = await res.json();

    const analysisDiv = el("password-analysis");
    const resultDiv = el("password-result");
    analysisDiv.style.display = "block";

    resultDiv.innerHTML = `
      <p><strong>Status:</strong> ${j.status}</p>
      <p><strong>Message:</strong> ${j.message}</p>
    `;
  } catch (err) {
    console.error(err);
    alert("Password check failed. Is the backend running?");
  }
}

// -------------------------------
// NAVIGATION
// -------------------------------
el("tab-dashboard").addEventListener("click", () => {
  showView("dashboard");
  loadStats();
});

el("tab-history").addEventListener("click", () => {
  showView("history");
  loadHistory();
});

el("tab-scanner").addEventListener("click", () => showView("scanner"));
el("tab-password").addEventListener("click", () => showView("password"));

// BUTTONS
el("btn-scan").addEventListener("click", doScan);
el("btn-check-password").addEventListener("click", doPasswordCheck);

// INITIAL LOAD
showView("dashboard");
loadStats();

// -------------------------------
// THEME SWITCHER
// -------------------------------
const themeButton = el("btn-theme");

themeButton.addEventListener("click", () => {
  const themeLink = el("theme-link");
  const body = document.body;   // needed for gradient switching

  if (themeLink.getAttribute("href") === "style.css") {
    themeLink.setAttribute("href", "light.css");
    themeButton.innerText = "⚫";
    body.classList.add("light");      // enable light gradients
  } else {
    themeLink.setAttribute("href", "style.css");
    themeButton.innerText = "⚪";
    body.classList.remove("light");   // restore dark gradients
  }
});
