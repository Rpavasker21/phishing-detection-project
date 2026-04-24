document.getElementById('scan-btn').addEventListener('click', async () => {
  const btn = document.getElementById('scan-btn');
  const resultBox = document.getElementById('result-box');
  const predSpan = document.getElementById('pred');
  const confSpan = document.getElementById('conf');

  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    // Get current tab URL
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let contentToScan = tab.url;

    // Send to our backend API
    const response = await fetch('http://127.0.0.1:8000/api/v1/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ content: contentToScan })
    });

    if (!response.ok) {
      throw new Error("Server error");
    }

    const data = await response.json();

    // Display
    resultBox.style.display = 'block';
    predSpan.textContent = data.prediction;
    confSpan.textContent = "Confidence: " + data.confidence;

    if (data.prediction.includes("PHISHING")) {
      resultBox.className = "danger";
    } else {
      resultBox.className = "safe";
    }

  } catch (err) {
    resultBox.style.display = 'block';
    resultBox.className = "danger";
    predSpan.textContent = "Error connecting to server";
    confSpan.textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan Current Page';
  }
});
