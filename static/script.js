function fetchStatus() {
    $.get("/status", function(data) {
        // Update status text
        $("#statusText").text("Status: " + (data.running ? "Running" : "Stopped"))
                        .removeClass("bg-success bg-danger")
                        .addClass(data.running ? "bg-success" : "bg-danger");

        $("#muteText").text("Siren: " + (data.muted ? "Muted" : "Unmuted"))
                      .removeClass("bg-warning bg-secondary")
                      .addClass(data.muted ? "bg-warning" : "bg-secondary");

        $("#alertCount").text("Alerts: " + data.alert_count);

        // Update alert box
        const alerts = data.alerts.map(a => `<div>${a}</div>`).join("");
        $("#alertBox").html(alerts || "<small>No alerts yet</small>");

        // Update IP Table
        let ipRows = "";
        for (const ip in data.ip_table) {
            const entry = data.ip_table[ip];
            ipRows += `<tr>
                <td>${ip}</td>
                <td>${entry.type}</td>
                <td>${entry.location}</td>
                <td>${entry.count}</td>
            </tr>`;
        }
        $("#ipTableBody").html(ipRows);
    });
}

// Button Events
$("#startBtn").click(() => $.post("/start_ids", fetchStatus));
$("#stopBtn").click(() => $.post("/stop_ids", fetchStatus));
$("#muteBtn").click(() => {
    const isMuted = $("#muteText").text().includes("Muted");
    $.post(isMuted ? "/unmute" : "/mute", fetchStatus);
});

// Auto-refresh every 2s
setInterval(fetchStatus, 2000);
fetchStatus();
